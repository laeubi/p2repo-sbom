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
package org.eclipse.cbi.p2repo.sbom.eclipse.handlers;

import org.eclipse.cbi.p2repo.sbom.eclipse.ui.GenerateSBOMDialog;
import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.ui.handlers.HandlerUtil;

/**
 * Handler for the Generate SBOM command
 */
public class GenerateSBOMHandler extends AbstractHandler {

	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		Shell shell = HandlerUtil.getActiveShell(event);
		
		GenerateSBOMDialog dialog = new GenerateSBOMDialog(shell);
		if (dialog.open() == Window.OK) {
			// Dialog will handle the job creation and execution
		}
		
		return null;
	}

}
