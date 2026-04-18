package worker

import "github.com/AzozzALFiras/GoSigner/ipa/archive"

func ipaArchiveOpen(path string) (*archive.IPAReader, error) {
	return archive.OpenIPA(path)
}
