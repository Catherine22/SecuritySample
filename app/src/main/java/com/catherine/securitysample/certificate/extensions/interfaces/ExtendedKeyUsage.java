package com.catherine.securitysample.certificate.extensions.interfaces;

import java.util.List;

public interface ExtendedKeyUsage {
	List<String> getKeyPurposeIds();
}
