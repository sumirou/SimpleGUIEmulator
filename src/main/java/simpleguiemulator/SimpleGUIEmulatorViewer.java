package simpleguiemulator;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableModel;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;

public class SimpleGUIEmulatorViewer extends JPanel implements ActionListener {
	private JTable tableRegister;
	private JTable tableChanged;
	private JButton btnSet;
	private JButton btnRun;
	private JButton btnStep;
	private JButton btnReset;

	private EmulatorHelper emulator;
	private Program currentProgram;
	private ProgramSelection currentSelection;

	private final int STACK_BASE_ADDRESS = 0x1000;
	private final int STACK_POINTER_ADDRESS = 0x1200;
	
	/**
	 * Create the panel.
	 */
	public SimpleGUIEmulatorViewer(EmulatorHelper emulator, Program currentProgram) {

		this.emulator = emulator;
		this.currentProgram = currentProgram;

		setLayout(null);

		JTextArea txtrRegisters = new JTextArea();
		txtrRegisters.setText("Registers");
		txtrRegisters.setEditable(false);
		txtrRegisters.setBounds(12, 41, 115, 22);
		add(txtrRegisters);

		btnSet = new JButton("Set");
		btnSet.addActionListener(this);
		btnSet.setBounds(12, 10, 91, 21);
		add(btnSet);

		btnRun = new JButton("Run");
		btnRun.addActionListener(this);
		btnRun.setBounds(110, 10, 91, 21);
		add(btnRun);

		btnStep = new JButton("Step");
		btnStep.addActionListener(this);
		btnStep.setBounds(208, 10, 91, 21);
		add(btnStep);

		btnReset = new JButton("Reset");
		btnReset.addActionListener(this);
		btnReset.setBounds(305, 10, 91, 21);
		add(btnReset);

		JTextArea txtrChanged = new JTextArea();
		txtrChanged.setText("Changed");
		txtrChanged.setEditable(false);
		txtrChanged.setBounds(12, 328, 115, 22);
		add(txtrChanged);

		tableRegister = new JTable();
		DefaultTableModel tableRegisterModel = new DefaultTableModel(new String[] { "register", "value" }, 0) {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				if (columnIndex == 0) {
					return String.class;
				}
				if (columnIndex == 0) {
					return String.class;
				}
				throw new SimpleGUIEmulatorException("unknown columnIndex at tableRegisterModel::getColumnClass");
			}
		};

		tableRegister.setModel(tableRegisterModel);

		tableRegister.setBounds(12, 73, 252, 245);
		add(tableRegister);

		tableChanged = new JTable();
		DefaultTableModel tableChangedModel = new DefaultTableModel(new String[] { "address", "value" }, 0) {
			@SuppressWarnings({ "unused", "rawtypes" })
			public Class getClumnClass(int columnIndex) {
				if (columnIndex == 0) {
					return String.class;
				}
				if (columnIndex == 1) {
					return String.class;
				}
				throw new SimpleGUIEmulatorException("unknown columnIndex at tableChangedModel::getColumnClass");
			}
		};
		tableChanged.setModel(tableChangedModel);

		tableChanged.setBounds(12, 360, 252, 218);
		add(tableChanged);

	}

	private void InitializeEmulatorRegisters(long executionAddress) {
		emulator.writeRegister(emulator.getPCRegister(), executionAddress);
		emulator.writeRegister(emulator.getStackPointerRegister(), STACK_POINTER_ADDRESS);
	}

	public void setCurrentSelection(ProgramSelection currentSelection) {
		this.currentSelection = currentSelection;
	}

	public void changeRegisterValue(String name, String value) {
		DefaultTableModel model = (DefaultTableModel) tableRegister.getModel();
		for (int i = 0; i < model.getRowCount(); ++i) {
			String data = (String) model.getValueAt(i, 0);
			if (data == name) {
				model.setValueAt(value, i, 1);
				break;
			}
		}
	}

	public void updatePanel(UpdatePanelType updateType) {
		switch (updateType) {
		case REGISTER:
			updateRegisterPanel();
			break;
		case MEMORY:
			updateMemoryPanel();
			break;
		case ALL:
			updateRegisterPanel();
			updateMemoryPanel();
			break;
		default:
			break;
		}
	}

	private void updateRegisterPanel() {
		List<Register> regs = currentProgram.getLanguage().getRegisters();
		List<SimpleGUIEmulatorRegisterClass> regclass = regs.stream()
				.map((reg) -> {
					String name = reg.getName();
					String value = Integer.valueOf(reg.getOffset()).toString();
					return new SimpleGUIEmulatorRegisterClass(name, value);
				}).toList();
		rebuildRegisterValues(regclass);
	}

	private void updateMemoryPanel() {
		AddressSetView writeSet = emulator.getTrackedMemoryWriteSet();
		List<SimpleGUIEmulatorChangedValueClass> changed = new ArrayList<SimpleGUIEmulatorChangedValueClass>();
		for (AddressRange ar : writeSet) {
			String spaceName = ar.getAddressSpace().getName();
			if (spaceName == "ram") {
				String value = GetByteDataFromEmulator(ar);
				changed.add(new SimpleGUIEmulatorChangedValueClass(
						BigInteger.valueOf(ar.getMinAddress().getOffset()).toString(), value));
			}
		}
		rebuildChangedValues(changed);
	}

	private String GetByteDataFromEmulator(AddressRange addressRange) {
		List<Byte> byteData = new ArrayList<Byte>();
		for (Address a : addressRange) {
			byteData.add(emulator.readMemoryByte(a));
		}
		List<String> strList = byteData.stream().map((b) -> {
			return String.format("%02X", b);
		}).toList();
		return String.join(" ", strList);
	}
	
	public void rebuildRegisterValues(List<SimpleGUIEmulatorRegisterClass> regs) {
		DefaultTableModel model = (DefaultTableModel) tableRegister.getModel();
		model.setRowCount(0);
		for (var reg : regs) {
			model.addRow(new String[]{ reg.getRegisterName(), reg.getRegisterValue() });
		}
		validate();
		repaint();
	}
	
	public void rebuildChangedValues(List<SimpleGUIEmulatorChangedValueClass> cvs) {
		DefaultTableModel model = (DefaultTableModel) tableChanged.getModel();
		model.setRowCount(0);
		for (var cv : cvs) {
			model.addRow(new String[] { cv.getAddress(), cv.getValue() });
		}
		validate();
		repaint();
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		var source = e.getSource();
		if (source == btnSet) {
			if (currentSelection != null) {
				Address startAddress = currentSelection.getFirstRange().getMinAddress();
				emulator.writeRegister(emulator.getPCRegister(), startAddress.getOffset());
				changeRegisterValue(emulator.getPCRegister().getName(),
						BigInteger.valueOf(startAddress.getOffset()).toString());
			}
		} else if (source == btnRun) {
			while(isInSelection(emulator.getExecutionAddress())) {
				try {
					emulator.step(null);
				} catch (CancelledException err) {
					err.printStackTrace();
					return;
				}
			}
			updatePanel(UpdatePanelType.ALL);
		} else if (source == btnStep) {
			try {
				emulator.step(null);
			} catch (CancelledException err) {
				err.printStackTrace();
				return;
			}
			updatePanel(UpdatePanelType.ALL);
		} else if (source == btnReset) {
			InitializeEmulatorRegisters(currentSelection.getMinAddress().getOffset());
		}
	}

	private boolean isInSelection(Address address) {
		if (currentSelection == null) {
			return false;
		}
		var result = currentSelection.getRangeContaining(address);
		if (result == null) {
			return false;
		}
		return true;
	}
}
