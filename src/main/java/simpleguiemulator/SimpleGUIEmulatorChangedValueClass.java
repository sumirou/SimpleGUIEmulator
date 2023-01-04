package simpleguiemulator;

public class SimpleGUIEmulatorChangedValueClass {
	
	private String address;
	private String value;
	
	public SimpleGUIEmulatorChangedValueClass(String addr, String v) {
		this.setAddress(addr);
		this.setValue(v);
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
}