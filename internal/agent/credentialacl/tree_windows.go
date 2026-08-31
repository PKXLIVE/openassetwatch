//go:build windows

package credentialacl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxManagedCredentialEntries = 64
	managedSystemSID            = "S-1-5-18"
	managedLocalServiceSID      = "S-1-5-19"
	managedAdministratorsSID    = "S-1-5-32-544"
	managedEveryoneSID          = "S-1-1-0"
	managedAuthenticatedSID     = "S-1-5-11"
	managedUsersSID             = "S-1-5-32-545"

	managedCredentialDirectorySDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + serviceSID + ")"
	managedCredentialFileSDDL      = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;" + serviceSID + ")"
)

var managedCredentialPath = []string{"OpenAssetWatch", "Agent", "state", "credential"}

type managedTreePlan struct {
	directoryDescriptor string
	fileDescriptor      string
	trustedDirOwners    map[string]struct{}
	trustedFileOwners   map[string]struct{}
	trustedWriters      map[string]struct{}
}

func repairDefaultManagedTree(programData string) error {
	return repairManagedCredentialTree(programData, managedTreePlan{
		directoryDescriptor: managedCredentialDirectorySDDL,
		fileDescriptor:      managedCredentialFileSDDL,
		trustedDirOwners: managedSIDSet(
			managedSystemSID,
			managedAdministratorsSID,
		),
		trustedFileOwners: managedSIDSet(
			managedSystemSID,
			managedAdministratorsSID,
			managedLocalServiceSID,
			serviceSID,
		),
		trustedWriters: managedSIDSet(
			managedSystemSID,
			managedAdministratorsSID,
			serviceSID,
		),
	})
}

func repairManagedCredentialTree(programData string, plan managedTreePlan) error {
	programData = filepath.Clean(programData)
	volume := filepath.VolumeName(programData)
	if volume == "" || !filepath.IsAbs(programData) || strings.HasPrefix(volume, `\\`) {
		return errors.New("Windows ProgramData path must be an absolute local volume path")
	}
	volumeRoot := volume + string(os.PathSeparator)
	relativeProgramData, err := filepath.Rel(volumeRoot, programData)
	if err != nil || !filepath.IsLocal(relativeProgramData) {
		return errors.New("Windows ProgramData path escapes its local volume")
	}
	return repairManagedCredentialTreeFromRoot(volumeRoot, splitManagedPath(relativeProgramData), plan)
}

func repairManagedCredentialTreeFromRoot(trustedRoot string, programDataComponents []string, plan managedTreePlan) error {
	objects := make([]securedObject, 0, 12)
	defer func() { closeObjects(objects) }()
	root, err := openManagedObject(trustedRoot, true, false)
	if err != nil {
		return errors.New("open Windows volume root for credential ACL repair")
	}
	objects = append(objects, root)
	parent := root
	for index, component := range programDataComponents {
		object, openErr := openManagedRelativeObject(parent.handle, component, true, false, false, false)
		if openErr != nil {
			return fmt.Errorf("open Windows ProgramData path component %d without reparse traversal: %w", index, openErr)
		}
		objects = append(objects, object)
		parent = object
	}
	if err := requireManagedOwner(objects[len(objects)-1].handle, plan.trustedDirOwners); err != nil {
		return fmt.Errorf("validate Windows ProgramData ownership: %w", err)
	}

	var credentialDirectory securedObject
	for index, component := range managedCredentialPath {
		mutable := index == len(managedCredentialPath)-1
		object, openErr := openManagedRelativeObject(parent.handle, component, true, mutable, true, false)
		if openErr != nil {
			return fmt.Errorf("open managed credential path component %q safely", component)
		}
		objects = append(objects, object)
		if err := requireManagedOwner(object.handle, plan.trustedDirOwners); err != nil {
			return fmt.Errorf("validate managed credential path component %q ownership: %w", component, err)
		}
		if err := rejectUnreviewedManagedWrite(object.handle, plan.trustedWriters); err != nil {
			return fmt.Errorf("validate managed credential path component %q permissions: %w", component, err)
		}
		credentialDirectory = object
		parent = object
	}

	entries, err := readManagedDirectory(credentialDirectory.handle)
	if err != nil {
		return errors.New("enumerate bounded credential state")
	}
	if len(entries) > maxManagedCredentialEntries {
		return errors.New("credential directory entry limit exceeded")
	}
	children := make([]securedObject, 0, len(entries))
	for _, entry := range entries {
		child, openErr := openManagedRelativeObject(credentialDirectory.handle, entry.Name(), false, true, true, true)
		if openErr != nil {
			return errors.New("open credential directory entry safely")
		}
		objects = append(objects, child)
		if child.linkCount != 1 {
			return errors.New("credential directory entry has multiple hard links")
		}
		if err := requireManagedOwner(child.handle, plan.trustedFileOwners); err != nil {
			return fmt.Errorf("validate credential directory entry ownership: %w", err)
		}
		children = append(children, child)
	}

	// Validation completes before mutation. Every pinned handle denies delete
	// sharing, so no validated path component or file can be replaced between
	// the checks above and the handle-based security updates below.
	if err := applyManagedSecurity(credentialDirectory.handle, plan.directoryDescriptor); err != nil {
		return errors.New("protect credential directory security")
	}
	for _, child := range children {
		if err := applyManagedSecurity(child.handle, plan.fileDescriptor); err != nil {
			return errors.New("protect credential state file security")
		}
	}
	return nil
}

func splitManagedPath(path string) []string {
	if path == "." {
		return nil
	}
	return strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
}

func managedSIDSet(sids ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(sids))
	for _, sid := range sids {
		result[strings.ToUpper(sid)] = struct{}{}
	}
	return result
}

func openManagedObject(path string, directory, mutable bool) (securedObject, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return securedObject{}, errors.New("credential ACL path is invalid")
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if directory {
		access |= windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.SYNCHRONIZE
	}
	if mutable {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return securedObject{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return securedObject{}, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return securedObject{}, errors.New("credential ACL path contains a reparse point")
	}
	if isDirectory != directory {
		windows.CloseHandle(handle)
		if directory {
			return securedObject{}, errors.New("credential ACL ancestor is not a directory")
		}
		return securedObject{}, errors.New("credential state entry is not a regular file")
	}
	return securedObject{handle: handle, isDirectory: isDirectory, linkCount: information.NumberOfLinks}, nil
}

func openManagedRelativeObject(parent windows.Handle, name string, directory, mutable, pinName, exclusive bool) (securedObject, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return securedObject{}, errors.New("credential ACL path component is invalid")
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return securedObject{}, errors.New("credential ACL path component is invalid")
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if directory {
		access |= windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		if exclusive {
			// Request data access so Windows share-mode arbitration detects any
			// already-open reader or writer before security is changed in place.
			access |= windows.FILE_READ_DATA
		}
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	if mutable {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	share := uint32(0)
	if !exclusive {
		share = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
		if !pinName {
			share |= windows.FILE_SHARE_DELETE
		}
	}
	if err := windows.NtCreateFile(
		&handle,
		access,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		share,
		windows.FILE_OPEN,
		options,
		0,
		0,
	); err != nil {
		return securedObject{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return securedObject{}, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return securedObject{}, errors.New("credential ACL path contains a reparse point")
	}
	if isDirectory != directory {
		windows.CloseHandle(handle)
		if directory {
			return securedObject{}, errors.New("credential ACL ancestor is not a directory")
		}
		return securedObject{}, errors.New("credential state entry is not a regular file")
	}
	return securedObject{handle: handle, isDirectory: isDirectory, linkCount: information.NumberOfLinks}, nil
}

func readManagedDirectory(handle windows.Handle) ([]os.DirEntry, error) {
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(
		windows.CurrentProcess(), handle, windows.CurrentProcess(), &duplicate,
		0, false, windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(duplicate), "credential-state")
	if directory == nil {
		windows.CloseHandle(duplicate)
		return nil, errors.New("wrap credential directory handle")
	}
	defer directory.Close()
	entries := make([]os.DirEntry, 0, maxManagedCredentialEntries+1)
	for len(entries) <= maxManagedCredentialEntries {
		batch, err := directory.ReadDir(maxManagedCredentialEntries + 1 - len(entries))
		entries = append(entries, batch...)
		if len(entries) > maxManagedCredentialEntries || errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return entries, nil
		}
	}
	return entries, nil
}

func requireManagedOwner(handle windows.Handle, trusted map[string]struct{}) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if _, ok := trusted[strings.ToUpper(owner.String())]; !ok {
		return errors.New("unsafe owner")
	}
	return nil
}

func rejectUnreviewedManagedWrite(handle windows.Handle, trustedWriters map[string]struct{}) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("missing restrictive DACL")
	}
	writeMask := windows.ACCESS_MASK(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			0x00000040 | // FILE_DELETE_CHILD
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("managed credential path has an unsupported ACL entry")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&writeMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if _, trusted := trustedWriters[strings.ToUpper(sid.String())]; !trusted {
			return errors.New("unreviewed principal has write-capable access")
		}
	}
	return nil
}

func applyManagedSecurity(handle windows.Handle, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		group,
		dacl,
		nil,
	)
}
