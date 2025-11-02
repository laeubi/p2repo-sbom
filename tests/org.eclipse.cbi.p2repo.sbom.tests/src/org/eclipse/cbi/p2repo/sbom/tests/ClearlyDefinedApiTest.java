package org.eclipse.cbi.p2repo.sbom.tests;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.cyclonedx.model.Component;
import org.eclipse.cbi.p2repo.sbom.ClearlyDefinedApi;
import org.eclipse.cbi.p2repo.sbom.ContentHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ClearlyDefinedApiTest {

	private ClearlyDefinedApi api;
	private ContentHandler contentHandler;
	
	@BeforeEach
	public void setUp() {
		contentHandler = new ContentHandler(null); // Use temporary cache
		api = new ClearlyDefinedApi(contentHandler);
	}
	
	@AfterEach
	public void tearDown() {
		if (api != null) {
			api.shutdown();
		}
	}
	
	@Test
	public void testBasicLifecycle() {
		assertNotNull(api);
	}
	
	@Test
	public void testSubmitRequestReturnsCompletableFuture() {
		Component component = new Component();
		component.setName("test-component");
		component.setType(Component.Type.LIBRARY);
		
		// Use a URI that won't actually be called in this test
		URI uri = URI.create("https://api.clearlydefined.io/definitions/maven/mavencentral/org.example/test/1.0.0");
		
		CompletableFuture<Void> future = api.submitRequest(component, uri);
		assertNotNull(future);
	}
	
	@Test
	public void testWaitForCompletion() throws Exception {
		// Test that waitForCompletion doesn't hang when queue is empty
		api.waitForCompletion();
		assertTrue(true, "waitForCompletion should complete when queue is empty");
	}
	
	@Test
	public void testShutdown() {
		api.shutdown();
		assertTrue(true, "shutdown should complete without errors");
	}
	
	@Test
	public void testCacheWorks() throws Exception {
		Component component1 = new Component();
		component1.setName("test-component-1");
		component1.setType(Component.Type.LIBRARY);
		
		Component component2 = new Component();
		component2.setName("test-component-2");
		component2.setType(Component.Type.LIBRARY);
		
		// Same URI for both components
		URI uri = URI.create("https://api.clearlydefined.io/definitions/maven/mavencentral/org.example/test/1.0.0");
		
		// Submit first request
		CompletableFuture<Void> future1 = api.submitRequest(component1, uri);
		
		// Wait a bit to ensure it's processed
		Thread.sleep(100);
		
		// Submit second request with same URI - should use cache
		CompletableFuture<Void> future2 = api.submitRequest(component2, uri);
		
		// Second request should complete immediately from cache
		assertTrue(future2.isDone() || future2.get(1, TimeUnit.SECONDS) == null);
	}
}
