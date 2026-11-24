//go:build windows

package credentialacl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestManagedTreeRepairsInheritedCredentialState(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	credentialPath := filepath.Join(credentialDir, "credential.json")
	temporaryPath := filepath.Join(credentialDir, ".agent-credential-review.tmp")
	contents := map[string]string{
		credentialPath: "synthetic-credential-fixture",
		temporaryPath:  "synthetic-temporary-fixture",
	}
	for path, content := range contents {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	userSID := currentUserSID(t)
	addBroadReadForTest(t, credentialDir, userSID)
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(userSID)); err != nil {
		t.Fatal(err)
	}
	assertManagedSecurity(t, credentialDir, true, userSID)
	for path, content := range contents {
		assertManagedSecurity(t, path, false, userSID)
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != content {
			t.Fatalf("credential-state content changed during repair")
		}
	}
}

func TestManagedTreeFreshFileInheritsOnlyReviewedPrincipals(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	userSID := currentUserSID(t)
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(userSID)); err != nil {
		t.Fatal(err)
	}
	freshPath := filepath.Join(credentialDir, "credential.json")
	if err := os.WriteFile(freshPath, []byte("synthetic-fresh-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	object, err := openManagedObject(freshPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(object.handle)
	assertNoBroadAllowedACE(t, object.handle)
}

func TestManagedTreeRejectsUnsafeOwnerBeforeMutation(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	credentialPath := filepath.Join(credentialDir, "credential.json")
	if err := os.WriteFile(credentialPath, []byte("synthetic-preserved-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := testManagedTreePlan(currentUserSID(t))
	plan.trustedDirOwners = managedSIDSet(managedSystemSID)
	if err := repairTestManagedCredentialTree(programData, plan); err == nil || !strings.Contains(err.Error(), "unsafe owner") {
		t.Fatalf("repair error = %v, want unsafe-owner rejection", err)
	}
	content, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "synthetic-preserved-fixture" {
		t.Fatal("failed repair changed credential state")
	}
}

func TestManagedTreeRejectsUnreviewedAncestorWrite(t *testing.T) {
	programData, _ := createManagedCredentialTree(t)
	userSID := currentUserSID(t)
	ancestor := filepath.Join(programData, "OpenAssetWatch")
	applyTestSecurity(t, ancestor, "O:"+userSID+"G:"+userSID+"D:P(A;OICI;FA;;;"+userSID+")(A;OICI;GW;;;IU)")
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(userSID)); err == nil || !strings.Contains(err.Error(), "unreviewed principal") {
		t.Fatalf("repair error = %v, want unreviewed-writer rejection", err)
	}
}

func TestManagedTreeRejectsDeleteChildForUnreviewedPrincipal(t *testing.T) {
	programData, _ := createManagedCredentialTree(t)
	userSID := currentUserSID(t)
	ancestor := filepath.Join(programData, "OpenAssetWatch")
	applyTestSecurity(t, ancestor, "O:"+userSID+"G:"+userSID+"D:P(A;OICI;FA;;;"+userSID+")(A;;0x40;;;BU)")
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(userSID)); err == nil || !strings.Contains(err.Error(), "unreviewed principal") {
		t.Fatalf("repair error = %v, want delete-child rejection", err)
	}
}

func TestManagedTreeAllowsUnreviewedInheritOnlyWriter(t *testing.T) {
	programData, _ := createManagedCredentialTree(t)
	userSID := currentUserSID(t)
	ancestor := filepath.Join(programData, "OpenAssetWatch")
	applyTestSecurity(t, ancestor, "O:"+userSID+"G:"+userSID+"D:P(A;OICI;FA;;;"+userSID+")(A;OIIO;GW;;;BU)")
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(userSID)); err != nil {
		t.Fatalf("inherit-only ACE incorrectly rejected: %v", err)
	}
}

func TestManagedTreeRejectsNestedDirectory(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	if err := os.Mkdir(filepath.Join(credentialDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil {
		t.Fatal("nested credential-state directory was accepted")
	}
}

func TestManagedTreeRejectsHardLinkedState(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	credentialPath := filepath.Join(credentialDir, "credential.json")
	if err := os.WriteFile(credentialPath, []byte("synthetic-preserved-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(credentialPath, filepath.Join(programData, "credential-backup.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Fatalf("repair error = %v, want hard-link rejection", err)
	}
	content, err := os.ReadFile(credentialPath)
	if err != nil || string(content) != "synthetic-preserved-fixture" {
		t.Fatal("failed hard-link repair did not preserve credential state")
	}
}

func TestManagedTreeRejectsCredentialFileReparsePoint(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	target := filepath.Join(programData, "outside.json")
	if err := os.WriteFile(target, []byte("synthetic-outside-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(credentialDir, "credential.json")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil {
		t.Fatal("credential-file reparse point was accepted")
	}
}

func TestManagedTreeRejectsAncestorReparsePoint(t *testing.T) {
	programData := filepath.Join(t.TempDir(), "ProgramData")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(filepath.Join(outside, "Agent", "state", "credential"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(programData, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(programData, "OpenAssetWatch")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil {
		t.Fatal("ancestor reparse point was accepted")
	}
}

func TestManagedTreeRejectsFinalDirectoryReparsePoint(t *testing.T) {
	programData := filepath.Join(t.TempDir(), "ProgramData")
	stateDir := filepath.Join(programData, "OpenAssetWatch", "Agent", "state")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, "credential")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil {
		t.Fatal("credential-directory reparse point was accepted")
	}
}

func TestManagedTreeRejectsEntryOverflow(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	for index := 0; index <= maxManagedCredentialEntries; index++ {
		name := filepath.Join(credentialDir, fmt.Sprintf("entry-%03d", index))
		if err := os.WriteFile(name, []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("repair error = %v, want bounded-entry rejection", err)
	}
}

func TestManagedTreeFailsClosedWhileCredentialStateIsOpen(t *testing.T) {
	programData, credentialDir := createManagedCredentialTree(t)
	credentialPath := filepath.Join(credentialDir, "credential.json")
	const content = "synthetic-preserved-fixture"
	if err := os.WriteFile(credentialPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := repairTestManagedCredentialTree(programData, testManagedTreePlan(currentUserSID(t))); err == nil {
		t.Fatal("repair succeeded while credential state had an open handle")
	}
	actual, err := os.ReadFile(credentialPath)
	if err != nil || string(actual) != content {
		t.Fatal("failed open-handle repair did not preserve credential state")
	}
}

func TestProductionCredentialDescriptorsUseOnlyReviewedPrincipals(t *testing.T) {
	for _, descriptorText := range []string{managedCredentialDirectorySDDL, managedCredentialFileSDDL} {
		descriptor, err := windows.SecurityDescriptorFromString(descriptorText)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := descriptor.Owner()
		if err != nil || !strings.EqualFold(owner.String(), managedSystemSID) {
			t.Fatalf("production descriptor owner = %v, %v", owner, err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("production descriptor DACL = %v, %v", dacl, err)
		}
		actual := allowedACEs(t, dacl)
		for _, sid := range []string{managedSystemSID, managedAdministratorsSID, serviceSID} {
			if actual[strings.ToUpper(sid)] == 0 {
				t.Fatalf("production descriptor omits reviewed principal %s", sid)
			}
		}
		if len(actual) != 3 {
			t.Fatalf("production descriptor contains unexpected allow principals: %v", actual)
		}
	}
}

func createManagedCredentialTree(t *testing.T) (string, string) {
	t.Helper()
	programData := filepath.Join(t.TempDir(), "ProgramData")
	credentialDir := filepath.Join(programData, "OpenAssetWatch", "Agent", "state", "credential")
	if err := os.MkdirAll(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	userSID := currentUserSID(t)
	for _, path := range []string{
		programData,
		filepath.Join(programData, "OpenAssetWatch"),
		filepath.Join(programData, "OpenAssetWatch", "Agent"),
		filepath.Join(programData, "OpenAssetWatch", "Agent", "state"),
		credentialDir,
	} {
		applyTestSecurity(t, path, "O:"+userSID+"G:"+userSID+"D:P(A;OICI;FA;;;"+userSID+")")
	}
	return programData, credentialDir
}

func repairTestManagedCredentialTree(programData string, plan managedTreePlan) error {
	return repairManagedCredentialTreeFromRoot(
		filepath.Dir(programData),
		[]string{filepath.Base(programData)},
		plan,
	)
}

func testManagedTreePlan(userSID string) managedTreePlan {
	return managedTreePlan{
		directoryDescriptor: "O:" + userSID + "G:" + userSID + "D:P(A;OICI;FA;;;" + userSID + ")",
		fileDescriptor:      "O:" + userSID + "G:" + userSID + "D:P(A;;FA;;;" + userSID + ")",
		trustedDirOwners:    managedSIDSet(userSID),
		trustedFileOwners:   managedSIDSet(userSID, managedAdministratorsSID),
		trustedWriters:      managedSIDSet(userSID),
	}
}

func addBroadReadForTest(t *testing.T, path, userSID string) {
	t.Helper()
	applyTestSecurity(t, path, "O:"+userSID+"G:"+userSID+"D:P(A;OICI;FA;;;"+userSID+")(A;OICI;GR;;;BU)")
}

func applyTestSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	object, err := openManagedObject(path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(object.handle)
	if err := applyManagedSecurity(object.handle, sddl); err != nil {
		t.Fatal(err)
	}
}

func assertManagedSecurity(t *testing.T, path string, directory bool, expectedOwner string) {
	t.Helper()
	object, err := openManagedObject(path, directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(object.handle)
	descriptor, err := windows.GetSecurityInfo(
		object.handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !strings.EqualFold(owner.String(), expectedOwner) {
		t.Fatalf("owner = %v, %v; want %s", owner, err, expectedOwner)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected: control=%v err=%v", control, err)
	}
	assertNoBroadAllowedACE(t, object.handle)
}

func assertNoBroadAllowedACE(t *testing.T, handle windows.Handle) {
	t.Helper()
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL = %v, %v", dacl, err)
	}
	actual := allowedACEs(t, dacl)
	for _, sid := range []string{managedEveryoneSID, managedAuthenticatedSID, managedUsersSID} {
		if actual[strings.ToUpper(sid)] != 0 {
			t.Fatalf("DACL grants broad principal %s access", sid)
		}
	}
}

func allowedACEs(t *testing.T, dacl *windows.ACL) map[string]windows.ACCESS_MASK {
	t.Helper()
	result := make(map[string]windows.ACCESS_MASK)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		result[strings.ToUpper(sid.String())] |= ace.Mask
	}
	return result
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}
