package ape

import (
	"testing"

	"time"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/jonhadfield/gogland-test/root"
)

type mockIAMClient struct {
	iamiface.IAMAPI
}

func (m *mockIAMClient) GetLoginProfile(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	now := time.Now().UTC()
	resetRequired := false
	loginProfile := iam.LoginProfile{
		CreateDate:            &now,
		UserName:              ptrToStr("Jon"),
		PasswordResetRequired: &resetRequired,
	}
	result := iam.GetLoginProfileOutput{
		LoginProfile: &loginProfile,
	}
	return &result, nil
}

func (m *mockIAMClient) ListMFADevicesOutput(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	now := time.Now().UTC()
	resetRequired := false
	loginProfile := iam.LoginProfile{
		CreateDate:            &now,
		UserName:              ptrToStr("Jon"),
		PasswordResetRequired: &resetRequired,
	}
	result := iam.GetLoginProfileOutput{
		LoginProfile: &loginProfile,
	}
	return &result, nil
}

func (m *mockIAMClient) ListMFADevices(input *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	now := time.Now().UTC()
	mfaDevice := &iam.MFADevice{
		UserName:     ptrToStr("Jon"),
		EnableDate:   &now,
		SerialNumber: ptrToStr("serialNo"),
	}

	mfaDevices := []*iam.MFADevice{mfaDevice}
	output := iam.ListMFADevicesOutput{
		MFADevices: mfaDevices,
	}
	return &output, nil
}

func (m *mockIAMClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	now := time.Now().UTC()
	accessKey1Metadata := iam.AccessKeyMetadata{
		UserName:    ptrToStr("Jon"),
		CreateDate:  &now,
		AccessKeyId: ptrToStr("AKIAIOSFODNN7EXAMPLE"),
		Status:      ptrToStr("Active"),
	}

	keys := []*iam.AccessKeyMetadata{
		&accessKey1Metadata,
	}

	output := iam.ListAccessKeysOutput{
		AccessKeyMetadata: keys,
	}

	return &output, nil
}

func (m *mockIAMClient) GetAccessKeyLastUsed(input *iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error) {
	now := time.Now().UTC()
	accessKeyLastUsed := iam.AccessKeyLastUsed{
		LastUsedDate: &now,
		Region:       ptrToStr("eu-west-1"),
		ServiceName:  ptrToStr("ec2"),
	}
	output := iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &accessKeyLastUsed,
		UserName:          ptrToStr("Jon"),
	}

	return &output, nil
}

func TestFilterHasMFADevice(t *testing.T) {
	mockSvc := &mockIAMClient{}
	filter := root.Filter{
		Criterion: "HasMFADevice",
		Value:     "true",
	}
	user := &iam.User{
		UserName: ptrToStr("Jon"),
	}
	result, err := filterHasMFADevice(mockSvc, user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports user doesn't have MFA")
	}
}

func TestFilterHasPassword(t *testing.T) {
	mockSvc := &mockIAMClient{}
	filter := root.Filter{
		Criterion: "HasPassword",
		Value:     "true",
	}
	user := &iam.User{
		UserName: ptrToStr("Jon"),
	}
	result, err := filterHasPassword(mockSvc, user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports user doesn't have password")
	}
}

func TestFilterPasswordLastUsed(t *testing.T) {
	filter := root.Filter{
		Criterion:  "PasswordLastUsed",
		Comparison: "<",
		Unit:       "days",
		Value:      "10",
	}
	now := time.Now().UTC()
	user := &iam.User{
		UserName:         ptrToStr("Jon"),
		PasswordLastUsed: &now,
	}
	result, err := filterPasswordLastUsed(user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports password last used not within valid time")
	}
}

func TestFilterAccessKeysLastUsed(t *testing.T) {
	mockSvc := &mockIAMClient{}
	filter := root.Filter{
		Criterion:  "AccessKeyLastUsed",
		Comparison: "<",
		Unit:       "days",
		Value:      "90",
	}
	now := time.Now().UTC()
	user := &iam.User{
		UserName:         ptrToStr("Jon"),
		PasswordLastUsed: &now,
		CreateDate:       &now,
		UserId:           ptrToStr("userid"),
		Path:             ptrToStr("path"),
		Arn:              ptrToStr("arn"),
	}
	input := filterAccessKeysLastUsedInput{
		svc:                        mockSvc,
		user:                       user,
		filter:                     &filter,
		rootAccessKey1Active:       false,
		rootAccessKey1LastUsedDate: now,
		rootAccessKey2Active:       false,
		rootAccessKey2LastUsedDate: now,
	}
	result, err := filterAccessKeysLastUsed(&input)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports access key last used not within valid time")
	}
}

func TestFilterActiveAccessKeysAge(t *testing.T) {
	mockSvc := &mockIAMClient{}
	filter := root.Filter{
		Criterion:  "ActiveAccessKeysAge",
		Comparison: "<",
		Unit:       "days",
		Value:      "90",
	}
	now := time.Now().UTC()
	user := &iam.User{
		UserName:         ptrToStr("Jon"),
		PasswordLastUsed: &now,
		CreateDate:       &now,
		UserId:           ptrToStr("userid"),
		Path:             ptrToStr("path"),
		Arn:              ptrToStr("arn"),
	}

	result, err := filterActiveAccessKeysAge(mockSvc, user, &filter)
	if err != nil {
		t.Errorf("function returned error: %s", err.Error())
	}
	if !result {
		t.Error("function reports active access key age didn't return mocked response")
	}
}

func TestFilterUserName(t *testing.T) {
	user := iam.User{
		UserName: ptrToStr("testUserName"),
	}
	filterOne := root.Filter{
		Criterion:  "UserName",
		Comparison: "in",
		Values:     []string{"userNameOne", "userNameTwo", "testUserName"},
	}
	filterTwo := root.Filter{
		Criterion:  "UserName",
		Comparison: "in",
		Values:     []string{"userNameOne", "userNameTwo", "userNameThree"},
	}
	goodMatch := filterUserName(&user, &filterOne)
	if !goodMatch {
		t.Error("match on existing username returned false")
	}
	noMatch := filterUserName(&user, &filterTwo)
	if noMatch {
		t.Error("match on missing username returned true")
	}

}
