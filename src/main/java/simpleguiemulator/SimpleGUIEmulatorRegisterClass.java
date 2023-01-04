package simpleguiemulator;

public class SimpleGUIEmulatorRegisterClass {
	
	private String registerName;
	private String registerValue;
	
	public SimpleGUIEmulatorRegisterClass(String name, String value) {
		this.setRegisterName(name);
		this.setRegisterValue(value);
	}

	public String getRegisterName() {
		return registerName;
	}

	public void setRegisterName(String registerName) {
		this.registerName = registerName;
	}

	public String getRegisterValue() {
		return registerValue;
	}

	public void setRegisterValue(String registerValue) {
		this.registerValue = registerValue;
	}
}
