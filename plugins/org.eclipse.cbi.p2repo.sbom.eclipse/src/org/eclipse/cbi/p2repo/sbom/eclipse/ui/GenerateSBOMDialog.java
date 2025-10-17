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
package org.eclipse.cbi.p2repo.sbom.eclipse.ui;

import java.io.File;
import java.nio.file.Path;

import org.eclipse.cbi.p2repo.sbom.eclipse.jobs.GenerateSBOMJob;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.DirectoryDialog;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.PlatformUI;

/**
 * Dialog for configuring SBOM generation settings
 */
public class GenerateSBOMDialog extends Dialog {

	private Text installationLocationText;
	private Text xmlOutputText;
	private Text jsonOutputText;
	private Button verboseCheck;
	private Button centralSearchCheck;
	private Button advisoryCheck;
	private Button processBundleClassPathCheck;
	
	private String installationLocation;
	private String xmlOutput;
	private String jsonOutput;
	private boolean verbose;
	private boolean centralSearch;
	private boolean advisory;
	private boolean processBundleClassPath;

	public GenerateSBOMDialog(Shell parentShell) {
		super(parentShell);
	}

	@Override
	protected void configureShell(Shell newShell) {
		super.configureShell(newShell);
		newShell.setText("Generate SBOM");
	}

	@Override
	protected Control createDialogArea(Composite parent) {
		Composite container = (Composite) super.createDialogArea(parent);
		GridLayout layout = new GridLayout(3, false);
		container.setLayout(layout);

		// Installation Location (auto-detected, read-only)
		Label installationLabel = new Label(container, SWT.NONE);
		installationLabel.setText("Installation Location:");
		installationLabel.setToolTipText("The Eclipse installation location (automatically detected)");

		installationLocationText = new Text(container, SWT.BORDER | SWT.READ_ONLY);
		installationLocationText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
		installationLocationText.setText(getEclipseInstallLocation());
		installationLocationText.setBackground(parent.getDisplay().getSystemColor(SWT.COLOR_WIDGET_BACKGROUND));
		
		// Empty cell for alignment
		new Label(container, SWT.NONE);

		// XML Output
		Label xmlOutputLabel = new Label(container, SWT.NONE);
		xmlOutputLabel.setText("XML Output:");
		xmlOutputLabel.setToolTipText("Optional path for the XML SBOM output file");

		xmlOutputText = new Text(container, SWT.BORDER);
		xmlOutputText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
		xmlOutputText.setText(getDefaultOutputPath(".xml"));

		Button xmlBrowseButton = new Button(container, SWT.PUSH);
		xmlBrowseButton.setText("Browse...");
		xmlBrowseButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				FileDialog dialog = new FileDialog(getShell(), SWT.SAVE);
				dialog.setFilterExtensions(new String[] { "*.xml", "*.*" });
				dialog.setFilterNames(new String[] { "XML Files", "All Files" });
				String result = dialog.open();
				if (result != null) {
					xmlOutputText.setText(result);
				}
			}
		});

		// JSON Output
		Label jsonOutputLabel = new Label(container, SWT.NONE);
		jsonOutputLabel.setText("JSON Output:");
		jsonOutputLabel.setToolTipText("Optional path for the JSON SBOM output file");

		jsonOutputText = new Text(container, SWT.BORDER);
		jsonOutputText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
		jsonOutputText.setText(getDefaultOutputPath(".json"));

		Button jsonBrowseButton = new Button(container, SWT.PUSH);
		jsonBrowseButton.setText("Browse...");
		jsonBrowseButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				FileDialog dialog = new FileDialog(getShell(), SWT.SAVE);
				dialog.setFilterExtensions(new String[] { "*.json", "*.*" });
				dialog.setFilterNames(new String[] { "JSON Files", "All Files" });
				String result = dialog.open();
				if (result != null) {
					jsonOutputText.setText(result);
				}
			}
		});

		// Options section
		Label optionsLabel = new Label(container, SWT.NONE);
		optionsLabel.setText("Options:");
		GridData optionsLabelData = new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1);
		optionsLabelData.verticalIndent = 10;
		optionsLabel.setLayoutData(optionsLabelData);

		// Verbose
		verboseCheck = new Button(container, SWT.CHECK);
		verboseCheck.setText("Verbose output");
		verboseCheck.setToolTipText("Enable verbose logging during SBOM generation");
		verboseCheck.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));

		// Central Search
		centralSearchCheck = new Button(container, SWT.CHECK);
		centralSearchCheck.setText("Search Maven Central");
		centralSearchCheck.setToolTipText("Query Maven Central for additional artifact information");
		centralSearchCheck.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));

		// Advisory
		advisoryCheck = new Button(container, SWT.CHECK);
		advisoryCheck.setText("Fetch advisories");
		advisoryCheck.setToolTipText("Query OSV database for security advisories");
		advisoryCheck.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));

		// Process Bundle Class Path
		processBundleClassPathCheck = new Button(container, SWT.CHECK);
		processBundleClassPathCheck.setText("Process Bundle-ClassPath");
		processBundleClassPathCheck.setToolTipText("Process nested JARs from Bundle-ClassPath manifest entries");
		processBundleClassPathCheck.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));

		// Add help button
		Label helpLabel = new Label(container, SWT.NONE);
		helpLabel.setText("For more information, see the help documentation.");
		helpLabel.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));

		return container;
	}

	@Override
	protected void createButtonsForButtonBar(Composite parent) {
		createButton(parent, IDialogConstants.HELP_ID, IDialogConstants.HELP_LABEL, false);
		createButton(parent, IDialogConstants.OK_ID, "Generate", true);
		createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
	}

	@Override
	protected void buttonPressed(int buttonId) {
		if (buttonId == IDialogConstants.HELP_ID) {
			PlatformUI.getWorkbench().getHelpSystem().displayHelp("org.eclipse.cbi.p2repo.sbom.eclipse.sbomGeneratorHelp");
		} else if (buttonId == IDialogConstants.OK_ID) {
			saveSettings();
			scheduleJob();
		}
		super.buttonPressed(buttonId);
	}

	private void saveSettings() {
		installationLocation = installationLocationText.getText();
		xmlOutput = xmlOutputText.getText().trim();
		jsonOutput = jsonOutputText.getText().trim();
		verbose = verboseCheck.getSelection();
		centralSearch = centralSearchCheck.getSelection();
		advisory = advisoryCheck.getSelection();
		processBundleClassPath = processBundleClassPathCheck.getSelection();
	}

	private void scheduleJob() {
		GenerateSBOMJob job = new GenerateSBOMJob(
			installationLocation,
			xmlOutput.isEmpty() ? null : xmlOutput,
			jsonOutput.isEmpty() ? null : jsonOutput,
			verbose,
			centralSearch,
			advisory,
			processBundleClassPath
		);
		job.setUser(true);
		job.schedule();
	}

	private static final java.util.regex.Pattern WINDOWS_PATH_PATTERN = 
			java.util.regex.Pattern.compile("^/[A-Za-z]:.*");
	
	private String getEclipseInstallLocation() {
		// Get the Eclipse installation location from the osgi.install.area property
		String installArea = System.getProperty("osgi.install.area");
		if (installArea != null) {
			// Remove the "file:" prefix if present
			if (installArea.startsWith("file:")) {
				installArea = installArea.substring(5);
			}
			// On Windows, remove leading slash
			if (WINDOWS_PATH_PATTERN.matcher(installArea).matches()) {
				installArea = installArea.substring(1);
			}
			return installArea;
		}
		return System.getProperty("user.dir", "");
	}

	private String getDefaultOutputPath(String extension) {
		String installLocation = getEclipseInstallLocation();
		if (installLocation == null || installLocation.isEmpty()) {
			return "";
		}
		try {
			Path path = Path.of(installLocation);
			String fileName = path.getFileName().toString() + "-sbom" + extension;
			Path parent = path.getParent();
			if (parent != null) {
				return parent.resolve(fileName).toString();
			}
			return fileName;
		} catch (java.nio.file.InvalidPathException e) {
			return "";
		}
	}
}
