// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

type GroupsClient interface {
	AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error
	GetGroup(ctx context.Context, objectID string) (result Group, err error)
	ListGroups(ctx context.Context, filter string) (result []Group, err error)
}

type Group struct {
	ID          string
	DisplayName string
}

func (c *MSGraphClient) AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error {
	req := models.NewReferenceCreate()
	odataId := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", memberObjectID)
	req.SetOdataId(&odataId)

	err := c.client.Groups().ByGroupId(groupObjectID).Members().Ref().Post(ctx, req, nil)
	if !isGroupMemberAlreadyPresent(err) {
		return err
	}

	// A previous POST may have succeeded without delivering its response. Do
	// not accept the duplicate message alone as proof of the exact membership.
	member, checkErr := c.client.Groups().ByGroupId(groupObjectID).Members().
		ByDirectoryObjectId(memberObjectID).GraphServicePrincipal().Get(ctx, nil)
	if checkErr != nil {
		return errors.Join(err, fmt.Errorf("verify existing group membership: %w", checkErr))
	}
	if member == nil || memberObjectID == "" || !strings.EqualFold(ptrToString(member.GetId()), memberObjectID) {
		return errors.Join(err, fmt.Errorf("verify existing group membership: missing or mismatched member ID"))
	}
	logVerifiedGroupMembership(ctx, groupObjectID, memberObjectID)
	return nil
}

func isGroupMemberAlreadyPresent(err error) bool {
	var graphErr *odataerrors.ODataError
	if !errors.As(err, &graphErr) || graphErr.GetStatusCode() != http.StatusBadRequest {
		return false
	}
	detail := graphErr.GetErrorEscaped()
	if detail == nil || detail.GetCode() == nil || detail.GetMessage() == nil {
		return false
	}
	code := strings.ToLower(*detail.GetCode())
	return (code == "request_badrequest" || code == "badrequest") &&
		strings.EqualFold(strings.TrimSpace(*detail.GetMessage()),
			"One or more added object references already exist for the following modified properties: 'members'.")
}

func (c *MSGraphClient) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error {
	err := ctx.Err()
	if err == nil {
		err = c.client.Groups().ByGroupId(groupObjectID).Members().ByDirectoryObjectId(memberObjectID).Ref().Delete(ctx, nil)
	}
	if err == nil || isGraphResourceNotFound(err) {
		return nil
	}
	return fmt.Errorf("remove group membership (group_object_id=%q, sp_object_id=%q%s): %w",
		groupObjectID, memberObjectID, GraphErrorDetails(err), err)
}

func (c *MSGraphClient) GetGroup(ctx context.Context, groupID string) (Group, error) {
	resp, err := c.client.Groups().ByGroupId(groupID).Get(ctx, nil)
	if err != nil {
		return Group{}, err
	}

	return getGroupResponse(resp), nil
}

func (c *MSGraphClient) ListGroups(ctx context.Context, filter string) ([]Group, error) {
	req := &groups.GroupsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}
	configuration := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: req,
	}

	groupList, err := c.client.Groups().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}

	var g []Group
	for _, group := range groupList.GetValue() {
		g = append(g, getGroupResponse(group))
	}

	return g, nil
}

func getGroupResponse(group models.Groupable) Group {
	if group != nil {
		return Group{
			ID:          ptrToString(group.GetId()),
			DisplayName: ptrToString(group.GetDisplayName()),
		}
	}

	// return zero-value result if app in nil
	// or fields can't be dereferenced
	return Group{
		ID:          "",
		DisplayName: "",
	}
}
