/**
 * Copyright (c) 2025 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.cyclonedx.model.Component;
import org.json.JSONObject;

import static org.eclipse.cbi.p2repo.sbom.BOMUtil.createProperty;

/**
 * Manager for ClearlyDefined API requests that handles rate limiting.
 * 
 * This class manages asynchronous requests to the ClearlyDefined API and respects
 * rate limits by monitoring the x-ratelimit-limit and x-ratelimit-remaining response
 * headers. It uses a fixed thread pool with 9 threads (1 queue processor + 8 workers)
 * to process requests asynchronously.
 */
public class ClearlyDefinedApi {
	
	/**
	 * Request to be processed by the ClearlyDefined API
	 */
	private static class ClearlyDefinedRequest {
		final Component component;
		final URI uri;
		final CompletableFuture<Void> future;
		int retryCount;
		
		ClearlyDefinedRequest(Component component, URI uri) {
			this.component = component;
			this.uri = uri;
			this.future = new CompletableFuture<>();
			this.retryCount = 0;
		}
	}
	
	private final HttpClient httpClient;
	private final BlockingQueue<ClearlyDefinedRequest> requestQueue;
	private final ExecutorService executorService;
	private final ConcurrentHashMap<URI, String> cache;
	private final ConcurrentHashMap<CompletableFuture<Void>, Boolean> activeFutures;
	
	private final AtomicInteger rateLimitRemaining;
	private final AtomicInteger rateLimitTotal;
	private final AtomicLong rateLimitResetTime;
	
	private volatile boolean shutdown;
	private final Thread queueProcessor;
	
	private static final int MAX_RETRIES = 3;
	private static final int WORKER_THREADS = 8;
	private static final int TOTAL_THREADS = WORKER_THREADS + 1; // +1 for queue processor
	
	public ClearlyDefinedApi() {
		this.httpClient = HttpClient.newBuilder()
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();
		this.requestQueue = new LinkedBlockingQueue<>();
		this.executorService = Executors.newFixedThreadPool(WORKER_THREADS);
		this.cache = new ConcurrentHashMap<>();
		this.activeFutures = new ConcurrentHashMap<>();
		
		this.rateLimitRemaining = new AtomicInteger(-1); // -1 means unknown
		this.rateLimitTotal = new AtomicInteger(-1);
		this.rateLimitResetTime = new AtomicLong(0);
		
		this.shutdown = false;
		
		// Start queue processor thread
		this.queueProcessor = new Thread(this::processQueue, "ClearlyDefined-Queue-Processor");
		this.queueProcessor.setDaemon(true);
		this.queueProcessor.start();
	}
	
	/**
	 * Submit a request to fetch ClearlyDefined information for a component.
	 * The request is queued and will be processed asynchronously.
	 * 
	 * @param component the component to enrich with ClearlyDefined data
	 * @param uri the ClearlyDefined API URI
	 * @return a CompletableFuture that completes when the request is processed
	 */
	public CompletableFuture<Void> submitRequest(Component component, URI uri) {
		// Check cache first
		String cached = cache.get(uri);
		if (cached != null) {
			updateComponent(component, cached);
			return CompletableFuture.completedFuture(null);
		}
		
		ClearlyDefinedRequest request = new ClearlyDefinedRequest(component, uri);
		activeFutures.put(request.future, Boolean.TRUE);
		request.future.whenComplete((v, e) -> activeFutures.remove(request.future));
		requestQueue.offer(request);
		return request.future;
	}
	
	/**
	 * Wait for all pending requests to complete.
	 * 
	 * @throws InterruptedException if the wait is interrupted
	 */
	public void waitForCompletion() throws InterruptedException {
		// Wait until the queue is empty and all futures are complete
		while (!requestQueue.isEmpty() || hasActiveFutures()) {
			Thread.sleep(100);
		}
	}
	
	/**
	 * Shutdown the API and release resources.
	 */
	public void shutdown() {
		shutdown = true;
		queueProcessor.interrupt();
		executorService.shutdown();
		try {
			executorService.awaitTermination(30, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
	
	private boolean hasActiveFutures() {
		return !activeFutures.isEmpty();
	}
	
	/**
	 * Main queue processing loop.
	 * Monitors rate limits and spawns worker tasks as capacity allows.
	 */
	private void processQueue() {
		while (!shutdown && !Thread.currentThread().isInterrupted()) {
			try {
				// Check if we need to wait for rate limit reset
				if (rateLimitRemaining.get() == 0) {
					long resetTime = rateLimitResetTime.get();
					long now = System.currentTimeMillis();
					if (resetTime > now) {
						long waitTime = resetTime - now;
						System.err.println("Rate limit exhausted, waiting " + (waitTime / 1000) + " seconds for reset");
						Thread.sleep(waitTime);
						// Reset the counter - actual value will be updated on next request
						rateLimitRemaining.set(-1);
					}
				}
				
				// Try to take a request from the queue
				ClearlyDefinedRequest request = requestQueue.poll(1, TimeUnit.SECONDS);
				if (request == null) {
					continue;
				}
				
				// If we don't know the rate limit yet, or we have capacity, submit the task
				int remaining = rateLimitRemaining.get();
				if (remaining == -1 || remaining > 0) {
					executorService.submit(() -> processRequest(request));
				} else {
					// No capacity, put it back in the queue
					requestQueue.offer(request);
					Thread.sleep(1000); // Wait a bit before retrying
				}
				
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				break;
			}
		}
	}
	
	/**
	 * Process a single ClearlyDefined request.
	 */
	private void processRequest(ClearlyDefinedRequest request) {
		try {
			HttpRequest httpRequest = HttpRequest.newBuilder(request.uri)
					.GET()
					.build();
			
			HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
			
			// Update rate limit information from response headers
			updateRateLimitInfo(response);
			
			int statusCode = response.statusCode();
			
			if (statusCode == 200) {
				// Success - cache the response and update component
				String body = response.body();
				cache.put(request.uri, body);
				updateComponent(request.component, body);
				request.future.complete(null);
				
			} else if (statusCode == 429) {
				// Rate limited - requeue if retries left
				if (request.retryCount < MAX_RETRIES) {
					request.retryCount++;
					System.err.println("Rate limited (429), re-queuing request (retry " + request.retryCount + "/" + MAX_RETRIES + "): " + request.uri);
					requestQueue.offer(request);
					
					// Update our rate limit counter to 0 to trigger waiting
					rateLimitRemaining.set(0);
					
					// Extract retry-after header if available
					String retryAfter = response.headers().firstValue("Retry-After").orElse(null);
					if (retryAfter != null) {
						try {
							long retryAfterSeconds = Long.parseLong(retryAfter);
							rateLimitResetTime.set(System.currentTimeMillis() + (retryAfterSeconds * 1000));
						} catch (NumberFormatException e) {
							// Ignore if not a number
						}
					}
				} else {
					request.future.completeExceptionally(
							new IOException("Max retries exceeded for ClearlyDefined request: " + request.uri));
				}
				
			} else if (statusCode == 404) {
				// Not found - complete normally (component won't be updated)
				request.future.complete(null);
				
			} else {
				// Other error - fail the request
				request.future.completeExceptionally(
						new IOException("ClearlyDefined request failed with status " + statusCode + ": " + request.uri));
			}
			
		} catch (IOException | InterruptedException e) {
			if (request.retryCount < MAX_RETRIES) {
				request.retryCount++;
				requestQueue.offer(request);
			} else {
				request.future.completeExceptionally(e);
			}
		}
	}
	
	/**
	 * Update rate limit tracking based on response headers.
	 */
	private void updateRateLimitInfo(HttpResponse<?> response) {
		response.headers().firstValue("x-ratelimit-limit").ifPresent(value -> {
			try {
				rateLimitTotal.set(Integer.parseInt(value));
			} catch (NumberFormatException e) {
				System.err.println("Invalid x-ratelimit-limit header: " + value);
			}
		});
		
		response.headers().firstValue("x-ratelimit-remaining").ifPresent(value -> {
			try {
				int remaining = Integer.parseInt(value);
				rateLimitRemaining.set(remaining);
				if (remaining == 0) {
					// If we hit the limit, try to get the reset time
					response.headers().firstValue("x-ratelimit-reset").ifPresent(resetValue -> {
						try {
							// Reset time might be in seconds since epoch
							long resetEpoch = Long.parseLong(resetValue);
							rateLimitResetTime.set(resetEpoch * 1000); // Convert to milliseconds
						} catch (NumberFormatException e) {
							System.err.println("Invalid x-ratelimit-reset header: " + resetValue);
						}
					});
				}
			} catch (NumberFormatException e) {
				System.err.println("Invalid x-ratelimit-remaining header: " + value);
			}
		});
	}
	
	/**
	 * Update a component with ClearlyDefined data from JSON response.
	 */
	private void updateComponent(Component component, String jsonContent) {
		try {
			JSONObject clearlyDefinedJSON = new JSONObject(jsonContent);
			JSONObject clearlyDefinedLicensed = clearlyDefinedJSON.getJSONObject("licensed");
			if (clearlyDefinedLicensed.has("declared")) {
				Object clearlyDefinedDeclaredLicense = clearlyDefinedLicensed.get("declared");
				if (clearlyDefinedDeclaredLicense instanceof String value) {
					component.addProperty(createProperty("clearly-defined", value));
				}
			}
		} catch (RuntimeException ex) {
			System.err.println("Bad ClearlyDefined content: " + ex.getMessage());
		}
	}
}
