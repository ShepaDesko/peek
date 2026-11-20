//go:build !unix

package store

// alignOwnership only has meaning where the service runs under its own
// account, which is the Linux deployment.
func alignOwnership(string) {}
