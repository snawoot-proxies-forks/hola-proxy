package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

const DEFAULT_LIST_LIMIT = 3

func CredService(interval, timeout time.Duration,
	extVer string,
	country string,
	proxytype string,
	logger *CondLogger,
	backoffInitial time.Duration,
	backoffDeadline time.Duration,
) (auth AuthProvider, tunnels *ZGetTunnelsResponse, err error) {
	var mux sync.Mutex
	var auth_header, user_uuid string
	auth = func() (res string) {
		mux.Lock()
		defer mux.Unlock()
		return auth_header
	}

	tx_err := EnsureTransaction(context.Background(), timeout, func(ctx context.Context, client *http.Client) error {
		tunnels, user_uuid, err = Tunnels(ctx, logger, client, extVer, country, proxytype,
			DEFAULT_LIST_LIMIT, timeout, backoffInitial, backoffDeadline)
		if err != nil {
			logger.Error("Configuration bootstrap error: %v. Retrying with the fallback mechanism...", err)
		}
		return err
	})
	if tx_err != nil {
		logger.Critical("Transaction recovery mechanism failure: %v", tx_err)
		err = tx_err
		return
	}
	auth_header = basic_auth_header(TemplateLogin(user_uuid), tunnels.AgentKey)
	if interval <= 0 {
		return
	}
	go func() {
		var (
			err       error
			tuns      *ZGetTunnelsResponse
			user_uuid string
		)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			<-ticker.C
			logger.Info("Rotating credentials...")
			tx_err := EnsureTransaction(context.Background(), timeout, func(ctx context.Context, client *http.Client) error {
				tuns, user_uuid, err = Tunnels(ctx, logger, client, extVer, country, proxytype,
					DEFAULT_LIST_LIMIT, timeout, backoffInitial, backoffDeadline)
				if err != nil {
					logger.Error("Credential rotation error: %v. Retrying with the fallback mechanism...", err)
				}
				return err
			})
			if tx_err != nil {
				logger.Critical("Transaction recovery mechanism failure: %v", tx_err)
				if errors.Is(tx_err, PermanentBanError) {
					// Stop rotating: each retry would only re-register
					// into the same ban.
					return
				}
				continue
			}
			mux.Lock()
			auth_header = basic_auth_header(TemplateLogin(user_uuid), tuns.AgentKey)
			mux.Unlock()
			logger.Info("Credentials rotated successfully.")
		}
	}()
	return
}
