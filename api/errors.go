// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

func isGraphResourceNotFound(err error) bool {
	// Do not suppress a multi-error that may also contain a permission failure.
	for err != nil {
		if graphErr, ok := err.(*odataerrors.ODataError); ok {
			detail := graphErr.GetErrorEscaped()
			return graphErr.GetStatusCode() == http.StatusNotFound && detail != nil &&
				strings.EqualFold(ptrToString(detail.GetCode()), "Request_ResourceNotFound")
		}
		err = errors.Unwrap(err)
	}
	return false
}

func graphDeleteError(err error, operation, objectID string) error {
	if err == nil || isGraphResourceNotFound(err) {
		return nil
	}
	return fmt.Errorf("%s (object_id=%q%s): %w", operation, objectID, GraphErrorDetails(err), err)
}

// GraphErrorDetails includes only status and correlation metadata, not response
// bodies, request headers, or credentials.
func GraphErrorDetails(err error) string {
	var graphErr *odataerrors.ODataError
	if !errors.As(err, &graphErr) {
		return ""
	}
	var code, requestID, graphDate string
	if detail := graphErr.GetErrorEscaped(); detail != nil {
		code = ptrToString(detail.GetCode())
		if inner := detail.GetInnerError(); inner != nil {
			requestID = ptrToString(inner.GetRequestId())
			if inner.GetDate() != nil {
				graphDate = graphUTCDate(*inner.GetDate()).Format(time.RFC3339Nano)
			}
		}
	}
	if headers := graphErr.GetResponseHeaders(); headers != nil {
		if ids := headers.Get("request-id"); len(ids) > 0 {
			requestID = strings.Join(ids, ",")
		}
	}
	return fmt.Sprintf(", graph_status=%d, graph_code=%q, graph_request_id=%q, graph_date=%q",
		graphErr.GetStatusCode(), code, requestID, graphDate)
}

// Graph sends innerError.date as UTC without a zone designator, and Kiota
// appends the host's current local offset (time.Now()) when parsing it. Undo
// that by reinterpreting the wall-clock time as UTC. Values that arrived with
// "Z" or a different explicit offset are converted normally.
func graphUTCDate(t time.Time) time.Time {
	_, offset := t.Zone()
	_, nowOffset := time.Now().Zone()
	if t.Location() == time.UTC || offset != nowOffset {
		return t.UTC()
	}
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}
