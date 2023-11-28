package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
	"github.com/sirupsen/logrus"
)

func (svc *Service) HandleListPaymentsEvent(ctx context.Context, request *Nip47Request, event *nostr.Event, app App, ss []byte) (result *nostr.Event, err error) {
	// TODO: move to a shared function
	nostrEvent := NostrEvent{App: app, NostrId: event.ID, Content: event.Content, State: "received"}
	err = svc.db.Create(&nostrEvent).Error
	if err != nil {
		svc.Logger.WithFields(logrus.Fields{
			"eventId":   event.ID,
			"eventKind": event.Kind,
			"appId":     app.ID,
		}).Errorf("Failed to save nostr event: %v", err)
		return nil, err
	}

	// TODO: move to a shared function
	hasPermission, code, message := svc.hasPermission(&app, event, request.Method, nil)

	if !hasPermission {
		svc.Logger.WithFields(logrus.Fields{
			"eventId":   event.ID,
			"eventKind": event.Kind,
			"appId":     app.ID,
		}).Errorf("App does not have permission: %s %s", code, message)

		return svc.createResponse(event, Nip47Response{
			ResultType: request.Method,
			Error: &Nip47Error{
				Code:    code,
				Message: message,
			}}, ss)
	}

	// TODO: move to a shared generic function
	listPaymentsParams := &Nip47ListPaymentsParams{}
	err = json.Unmarshal(request.Params, listPaymentsParams)
	if err != nil {
		svc.Logger.WithFields(logrus.Fields{
			"eventId":   event.ID,
			"eventKind": event.Kind,
			"appId":     app.ID,
		}).Errorf("Failed to decode nostr event: %v", err)
		return nil, err
	}

	svc.Logger.WithFields(logrus.Fields{
		"eventId":   event.ID,
		"eventKind": event.Kind,
		"appId":     app.ID,
		"from":      listPaymentsParams.From,
		"until":     listPaymentsParams.Until,
		"limit":     listPaymentsParams.Limit,
		"offset":    listPaymentsParams.Offset,
	}).Info("Looking up invoice")

	res, err := svc.lnClient.ListPayments(ctx, event.PubKey, listPaymentsParams)

	if err != nil {
		svc.Logger.WithFields(logrus.Fields{
			"eventId":   event.ID,
			"eventKind": event.Kind,
			"appId":     app.ID,
			"from":      listPaymentsParams.From,
			"until":     listPaymentsParams.Until,
			"limit":     listPaymentsParams.Limit,
			"offset":    listPaymentsParams.Offset,
		}).Infof("Failed to lookup invoice: %v", err)
		nostrEvent.State = NOSTR_EVENT_STATE_HANDLER_ERROR
		svc.db.Save(&nostrEvent)
		return svc.createResponse(event, Nip47Response{
			ResultType: NIP_47_LOOKUP_INVOICE_METHOD,
			Error: &Nip47Error{
				Code:    NIP_47_ERROR_INTERNAL,
				Message: fmt.Sprintf("Something went wrong while looking up invoice: %s", err.Error()),
			},
		}, ss)
	}

	responsePayload := &Nip47LookupInvoiceResponse{
		Invoice: invoice,
		Paid:    paid,
	}

	nostrEvent.State = NOSTR_EVENT_STATE_HANDLER_EXECUTED
	svc.db.Save(&nostrEvent)
	return svc.createResponse(event, Nip47Response{
		ResultType: NIP_47_LOOKUP_INVOICE_METHOD,
		Result:     responsePayload,
	},
		ss)
}
