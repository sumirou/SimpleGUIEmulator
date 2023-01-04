/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package simpleguiemulator;

import java.math.BigInteger;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

enum UpdatePanelType {
	REGISTER,
	MEMORY,
	ALL,
}

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "SimpleGUIEmulator.",
	description = "simple gui for pcode emulator"
)

//@formatter:on
public class SimpleGUIEmulatorPlugin extends ProgramPlugin {

	MyProvider provider;
	private EmulatorHelper emulator;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SimpleGUIEmulatorPlugin(PluginTool tool) {
		super(tool);

		// initialize emulator
		if (currentProgram != null) {
			emulator = new EmulatorHelper(currentProgram);
		} else {
			emulator = null;
		}

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName, currentProgram, emulator);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
	}
	
	@Override
	protected void programClosed(Program program) {
		emulator.dispose();
	}
	
	@Override
	protected void programOpened(Program program) {
		emulator = new EmulatorHelper(currentProgram);
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		var addr = loc.getAddress();
		var reg = emulator.getPCRegister();
		emulator.setContextRegister(reg, BigInteger.valueOf(addr.getOffset()));
		provider.getComponent().updatePanel(UpdatePanelType.REGISTER);
	}
	
	@Override
	protected void selectionChanged(ProgramSelection sel) {
		var panel = provider.getComponent();
		panel.setCurrentSelection(sel);
	}
	
	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private SimpleGUIEmulatorViewer panel;
		private DockingAction action;
		private ProgramPlugin plugin;
		private Program currentProgram;
		private EmulatorHelper emulator;
		private ProgramSelection currentSelection;

		public MyProvider(ProgramPlugin plugin, String owner, Program program, EmulatorHelper emulator) throws SimpleGUIEmulatorException {
			super(plugin.getTool(), owner, owner);
			this.plugin = plugin;
			this.emulator = emulator;
			this.currentProgram = program;
			buildPanel();
			createActions();
		}

		public void dispose() {
			// currently do nothing
		}
		
		// Customize GUI
		private void buildPanel() throws SimpleGUIEmulatorException {
			panel = new SimpleGUIEmulatorViewer(emulator, currentProgram);
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public SimpleGUIEmulatorViewer getComponent() {
			return panel;
		}
	}
}
