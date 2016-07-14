package cas

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/golang/glog"
)

var sessionCookieName = "_cas_session"
var cookieNameMu sync.Mutex

func SetCookieName(name string) {
	cookieNameMu.Lock()
	sessionCookieName = name
	cookieNameMu.Unlock()
}

// clientHandler handles CAS Protocol HTTP requests
type clientHandler struct {
	c *Client
	h http.Handler
}

// ServeHTTP handles HTTP requests, processes CAS requests
// and passes requests up to its child http.Handler.
func (ch *clientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if glog.V(2) {
		glog.Infof("cas: handling %v request for %v", r.Method, r.URL)
	}

	SetClient(r, ch.c)
	defer Clear(r)

	if IsSingleLogoutRequest(r) {
		ch.performSingleLogout(w, r)
		return
	}

	ch.c.GetSession(w, r)
	ch.h.ServeHTTP(w, r)
	return
}

// isSingleLogoutRequest determines if the http.Request is a CAS Single Logout Request.
//
// The rules for a SLO request are, HTTP POST urlencoded form with a logoutRequest parameter.
func IsSingleLogoutRequest(r *http.Request) bool {
	if r.Method != "POST" {
		return false
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return false
	}

	if v := r.FormValue("logoutRequest"); v == "" {
		return false
	}

	return true
}

// performSingleLogout processes a single logout request
func (ch *clientHandler) performSingleLogout(w http.ResponseWriter, r *http.Request) {
	rawXML := r.FormValue("logoutRequest")
	logoutRequest, err := ParseLogoutRequest([]byte(rawXML))

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := ch.c.tickets.Delete(logoutRequest.SessionIndex); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ch.c.DeleteSession(logoutRequest.SessionIndex)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
