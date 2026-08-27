//go:build windows

package credentialacl

import (
	"errors"

	"golang.org/x/sys/windows"
)

const serviceSID = "S-1-5-80-630466807-4251148593-2853048944-3410275790-4186592652"

type securedObject struct {
	handle      windows.Handle
	isDirectory bool
	linkCount   uint32
}

// RepairDefault resolves ProgramData through the Windows known-folder API so
// an inherited environment variable cannot redirect the elevated MSI action.
func RepairDefault() error {
	programData, err := windows.KnownFolderPath(
		windows.FOLDERID_ProgramData,
		windows.KF_FLAG_DEFAULT,
	)
	if err != nil {
		return errors.New("resolve Windows ProgramData for credential ACL repair")
	}
	return repairDefaultManagedTree(programData)
}

func closeObjects(objects []securedObject) {
	for _, object := range objects {
		windows.CloseHandle(object.handle)
	}
}
