//go:build !darwin

package platform

// GetOrCreateKey is not implemented on this OS yet.
func GetOrCreateKey(service, account string) ([]byte, error) {
	if err := validateNames(service, account); err != nil {
		return nil, err
	}
	return nil, ErrNotSupported
}

// DeleteKey is not implemented on this OS yet.
func DeleteKey(service, account string) error {
	if err := validateNames(service, account); err != nil {
		return err
	}
	return ErrNotSupported
}
