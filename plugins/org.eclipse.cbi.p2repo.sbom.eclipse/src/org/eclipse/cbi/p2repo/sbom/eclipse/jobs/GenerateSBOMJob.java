/**
 * Copyright (c) 2023 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom.eclipse.jobs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.cbi.p2repo.sbom.SBOMApplication;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.equinox.app.IApplicationContext;

/**
 * Eclipse Job that generates an SBOM by calling the SBOMApplication
 */
public class GenerateSBOMJob extends Job {

	private final String installationLocation;
	private final String xmlOutput;
	private final String jsonOutput;
	private final boolean verbose;
	private final boolean centralSearch;
	private final boolean advisory;
	private final boolean processBundleClassPath;

	public GenerateSBOMJob(String installationLocation, String xmlOutput, String jsonOutput,
			boolean verbose, boolean centralSearch, boolean advisory, boolean processBundleClassPath) {
		super("Generate SBOM");
		this.installationLocation = installationLocation;
		this.xmlOutput = xmlOutput;
		this.jsonOutput = jsonOutput;
		this.verbose = verbose;
		this.centralSearch = centralSearch;
		this.advisory = advisory;
		this.processBundleClassPath = processBundleClassPath;
	}

	@Override
	protected IStatus run(IProgressMonitor monitor) {
		monitor.beginTask("Generating SBOM", IProgressMonitor.UNKNOWN);

		try {
			// Build the arguments list
			List<String> args = new ArrayList<>();
			
			if (verbose) {
				args.add("-verbose");
			}
			
			args.add("-installation");
			args.add(installationLocation);
			
			if (xmlOutput != null && !xmlOutput.isEmpty()) {
				args.add("-xml-output");
				args.add(xmlOutput);
			}
			
			if (jsonOutput != null && !jsonOutput.isEmpty()) {
				args.add("-json-output");
				args.add(jsonOutput);
			}
			
			if (centralSearch) {
				args.add("-central-search");
			}
			
			if (advisory) {
				args.add("-advisory");
			}
			
			if (processBundleClassPath) {
				args.add("-process-bundle-classpath");
			}

			// Create a mock application context
			IApplicationContext context = new IApplicationContext() {
				@Override
				public void applicationRunning() {
				}

				@Override
				public Map<?, ?> getArguments() {
					Map<String, Object> arguments = new HashMap<>();
					arguments.put("application.args", args.toArray(new String[0]));
					return arguments;
				}

				@Override
				public String getBrandingApplication() {
					return null;
				}

				@Override
				public String getBrandingBundle() {
					return null;
				}

				@Override
				public String getBrandingDescription() {
					return null;
				}

				@Override
				public String getBrandingId() {
					return null;
				}

				@Override
				public String getBrandingName() {
					return null;
				}

				@Override
				public String getBrandingProperty(String key) {
					return null;
				}

				@Override
				public void setResult(Object result, IApplicationContext context) {
				}
			};

			// Call the SBOMApplication
			SBOMApplication app = new SBOMApplication();
			app.start(context);

			if (monitor.isCanceled()) {
				return Status.CANCEL_STATUS;
			}

			return Status.OK_STATUS;

		} catch (Exception e) {
			return new Status(IStatus.ERROR, "org.eclipse.cbi.p2repo.sbom.eclipse",
					"Error generating SBOM: " + e.getMessage(), e);
		} finally {
			monitor.done();
		}
	}
}
