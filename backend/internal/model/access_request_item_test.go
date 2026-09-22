package model

import (
	"gorm.io/gorm"
	"testing"
)

func TestAccessRequestItemValidation(t *testing.T) {
	good := AccessRequestItem{RequestID: 1, RequesterID: 2, AssetID: 3, Status: AccessRequestPending}
	if err := good.BeforeCreate(&gorm.DB{}); err != nil || good.PolicySnapshot != "{}" {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AccessRequestItem){func(i *AccessRequestItem) { i.RequestID = 0 }, func(i *AccessRequestItem) { i.RequesterID = 0 }, func(i *AccessRequestItem) { i.AssetID = 0 }, func(i *AccessRequestItem) { i.Status = AccessRequestApproved }, func(i *AccessRequestItem) { i.PolicySnapshot = `[]` }} {
		bad := good
		mutate(&bad)
		if bad.BeforeCreate(&gorm.DB{}) == nil {
			t.Fatal("invalid item accepted", bad)
		}
	}
}
