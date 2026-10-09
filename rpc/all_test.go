// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rpc

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto"

	"upspin.io/cache"
	"upspin.io/cloud/https"
	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/log"
	prototest "upspin.io/rpc/testdata"
	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

var (
	joePublic = upspin.PublicKey("ML-DSA-44\nJOsTOS1f3Yx58d7_7RVRsh_jwQGPoJi3QQUN2lyauDiPPwq260pDOKhSfiTNVaxrzdF_avivG1mXxihhWo9uQJVwhWBe_6Fj9taudOF7hgFJOkGBgZeiUGK4_TpH68zTZdBjF4seiIC_Nu3Oc-Ie1UjJG_iHLnGhGiP-xVKWEc9yCuc73mg5Xtwr0rqQAZcZeJjFsKqawC7rIYcb3i_HqfDQQL3qOCBLrAdf3yJCgFB11_m2rKHpty7jwPZweIoRqexXIkx9CFA3UOlu1QiH5EJqUEyqfqK1BdP77ydODiGRDTEBqD0tMAgAmece-7sbYH3CkmjedguGL6djkzriMT-pRX3hTQyYLkWlJqobARUoPyAsQVp3eKIb19TD-RIKLX1vi-kCQ23lUu-M_iDvzTmyyZX0AsbACNk5b5h27_UeQiqHW7x2jQpLEf95a_bEnXoxZx6SvPHLz1D5eXQL9lEg3uiyaX-CIat06Gegt1_tYJEsCGVoyx8yolemNLonhfkUv7wJwZ9H2KJkHzCQbv_5kE6rZe0WvE73LPYy_PysmxWZczP1Vjov9wNN2cTbw19S5IcI0G8Hd3dAVabOT2GQz2yadd8kl8RS8gnKEqn0Jc7ZALDAfCx-1Z4cPUJXXUTeOiAi839Gum1aqoJ3Ue1G5FBpPDWTwEEf5FfiMOnOnQm599N32MURXCnVpiut_y0EFoQeLyucxNK96xdodzbHzoSm3U69ZSDPlw9ZwoAojIMG3XsVqQ5wQl9HPo4vZseodHaCHr0wYCNwI9eIWwj9xmPRyqmvD5UWsc-_3ywOtc8vQXGij1sCYrcgS8htiwKswDyu8HmUJb7GwBVr8FDd2KjEZ0-I5uzJkQ1HqmJ86mFOJKyPZNnQlsh94obyqESu9sbj0hmNH6-jP5YsxRN357mBqkG0mWSsr2-r44k0yDVjMsjm0y1_-vnqznoSaPGkmpMkynQs8-a0weevT_1CERIyDpuVH5QP6gRIscFM5d2WTwRVi9_EbZKLpNuz2NBPF_i_674mCCvS-4M1CrNTQVPKVRaLg4UqAk5EOYz6Pw43n7JtSp_LjIt-_LvH0po2h6NqbXod5oheDi9faFYb-5tBAfLlEyGgihGjtkum7594jg8FQHNcqdxmONoxoZ5VY4gNgeLGNnaplvVGspTjd_ollw3mzazVGOlbU1vpxnD0bGWAU4UKC9BZpKhkqVTegYIkPBHCgigSCclvEeySHCm0q67Kx2Wa-5LvZGPo4gSn6_n6OALYQOp9nTQZcicnOtj49pk1ZppAGDFR58S6pjBa_X8UI9ryOhG6gS3hVfvzzQBWn1RG7XtbKlou9FIAWX6Bjbw_nYRw4kfa-Q1pfVEAmzmFV60IjO2UhEB_KRy92TLs2bjo0awfSpSam-L9IJ02hTmh_dbrlkYG6QancpZOKeTzdItWk42WTo_x6YjC2wQkc_ted_9e6NSicAgbAtOYCenJr6h8zhIQmrXC8Gtn3juzwBbq9N6IMhT-NcakRN8pMF9XxNkqO4j16qwvrjD1F1wnFOTT95UDHOpoYs7WHTV_ODgM3EdbCc9g0ou5krgtJJa_Jd62719ygQYdPfGo5BqWiLC6aK-cOkmre7220F4nRo-MgykYC4OAXUGCs8zib0GppoSAfmmOOeK89sMKPN87CUMtU6pfK728j2eUQC_OafpEGp9BnpHeY_9JaxjoZ94QXcl8isShIMBon322HfbZlG9Z0cmS7g\nmlkem768\ncYg3c2i9X4V8D9cIF5JqlHSAnZsSalMhzeur0SkmgBJzAoAQ79gsK2s51XwTl2FozPQIkdq4JkOpSDSe5cY7ezOWi9a8x1AFkElmfdmEP5pZn_azPqZL1IN8tWFaZSV9bSLFKRszLMSA8IZ5xrUZl8IB4VSSBQGxUQo4igpKnrO_lqktUoOcVIZ_o0JRq_fCC9KFG8s9XFM3ZGFTL9M6FSXEOmlMuBSANwgGH1Csr4jBojmwmrhU5nSHKxmedYONtvaDiJYPV-nOYvCj6EV2N7aXJmSjSvNBSmdmS_pRkIJoBqe8QjJtLHl5UfsJgOWXv4W8pfukyTitFfpntnQMJ-Ku7KwF58YkKTOh7eSL9Vs__rO8YKIJr1NTu-i-q9hOJTIXkjST_GZxteCEAkB8H_o4oPtsmjy3q1LKoJav7frG76UR4VCmCqNmelyGGYO9hlFVfgmghaud-JAgwPgH4ftp8fYz8OiQ5jsEYeXE9mkzhNqa8DkKaBxs8UK0KdqVkTE_5cdmulmDZJnLGHtDb2C5xtq1f_VYPCR85oVZoMQjTBm707oErpnGSGq-DGewllvJtSKYUqazjbsFQYiGGyA0APcvY2hTaGx7P0eq9psy99ZnGHxUrGF-7oR74OCsyiyyrXkvStA20gLPUgKQ3ys2bYY5_xGFdDAR0OjBiOvPchRX_xDHG9gydOCetxGgeunBH7YW5Te4q_qxCohVjMZVYlqxYaxvy4IYM2uuzoI_kspTPxvF4qYVZHuWpTCLReVbD8gDmZy4Q7OIb7lTnJhXr9SnuYHF7_Oee7RlvBajhJo_t9NkPLPPoQgdKkVlcoQLDJU6i4RbgZxQlcFkuRRUnqwNORQNG-Ojk4uDdUIMfsqV0yIB6YHPTPWMUjeEHxENxNoxj8eZbcAvqIhyQWjPekN8vORk3Cga5ft0w9JGA8EeNBBpGOKxOZIfjkweBeMkxNIU9JQq4YpcvRoLA8e3OrA7XEcBwjluRsQjJJZ_O1VrMicdEMwKojVpg-VceYEZfgq5LBO3yeYbuPlI08t2uBggEKEaGYAeP5K2QImSLrSPF6Z64YetVoOC7nygOQkbb4wwSce6GjBUqala78Oxz4nNFUk_SDoiQGhQVVWLJ6GAgNKQCDCao-VgtRd_b9xk8Vp3T4Wc7-tJqnSi7te0THBNvMIfVQbO3frKXZJQQ5gyx6eWUcJK9wcfs6EYTVgizIbEpxYy8lJLcnhcaCoE_ywd4UEjKlJJtadJHXZ89BCjXDNQ9-QFkfycDcuDlFS8t1tBkpwp-HoclJQ71_c49TpmlGVsA9BbZtCvysg2Wot2bbVXU3UjyjKTeroUejkyyBiaAqtXEPLAdHUdnpgRhXbIM2xkg0ctqFJv7sq6X9C1PmTI79A4EVGpLYgxLUMCFkkF8Lq-_Btlv2zNPcFqU-MTsJeaQlucwGKq7BF3YZcdEWdb1pOrvsVaOvaR3WYuMpeW8cyIcsNbhhCOT3JzxFV5ChQbVEwVw0NUaxUPKrd688Or8dFNJeWawNsvYd7UOjyxvMurR5482nwi6_3t64OU_6tvbxS1BXJ3EuU\n")
	joeUser   = upspin.UserName("joe@blow.com")
	srv       *server
	cli       *client
)

var payloads = []string{
	"The wren",
	"Earns his living",
	"Noiselessly.",
	// - Kobayahsi Issa
}

func lookup(user upspin.UserName) (upspin.PublicKey, error) {
	if user == joeUser {
		return upspin.PublicKey(joePublic), nil
	}
	return "", errors.E(errors.NotExist, "No user here")
}

type server struct {
	t         *testing.T
	iteration int
}

func startServer(t *testing.T) (port string) {
	srv = &server{t: t}
	var err error
	port, err = testutil.PickPort()
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.SetUserName(config.New(), "server@upspin.io")
	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	http.Handle("/api/Server/", NewServer(cfg, Service{
		Name: "Server",
		Methods: map[string]Method{
			"Echo": srv.Echo,
		},
		UnauthenticatedMethods: map[string]UnauthenticatedMethod{
			"UnauthenticatedEcho": srv.UnauthenticatedEcho,
		},
		Streams: map[string]Stream{
			"Count": srv.Count,
		},
		Lookup: lookup,
	}))

	ready := make(chan struct{})
	go https.ListenAndServe(ready, &https.Options{
		Addr: fmt.Sprintf("localhost:%s", port),
	})
	<-ready
	return port
}

func (s *server) UnauthenticatedEcho(reqBytes []byte) (pb.Message, error) {
	var req prototest.EchoRequest
	if err := pb.Unmarshal(reqBytes, &req); err != nil {
		return nil, err
	}
	if req.Payload == payloads[s.iteration] {
		resp := &prototest.EchoResponse{
			Payload: payloads[s.iteration],
		}
		log.Printf("Server: UnauthenticatedEcho response: %q", resp.Payload)
		s.iteration++
		return resp, nil
	}
	s.t.Fatalf("iteration %d: invalid request %q", s.iteration, req.Payload)
	return nil, nil // not reached
}

func (s *server) Echo(session Session, reqBytes []byte) (pb.Message, error) {
	var req prototest.EchoRequest
	if err := pb.Unmarshal(reqBytes, &req); err != nil {
		return nil, err
	}
	if session.User() != joeUser {
		s.t.Fatalf("Expected user %q, got %q", joeUser, session.User())
	}
	if req.Payload == payloads[s.iteration] {
		resp := &prototest.EchoResponse{
			Payload: payloads[s.iteration],
		}
		log.Printf("Server: Echo response: %q", resp.Payload)
		s.iteration++
		return resp, nil
	}
	s.t.Fatalf("iteration %d: invalid request %q", s.iteration, req.Payload)
	return nil, nil // not reached
}

func (s *server) Count(session Session, reqBytes []byte, done <-chan struct{}) (<-chan pb.Message, error) {
	var req prototest.CountRequest
	if err := pb.Unmarshal(reqBytes, &req); err != nil {
		return nil, err
	}
	log.Printf("Server: Count request: %d", req.Start)

	out := make(chan pb.Message)
	go func() {
		defer close(out)
		for i := req.Start; i < req.Start+req.Count; i++ {
			resp := &prototest.CountResponse{
				Number: i,
			}
			select {
			case out <- resp:
			case <-done:
				return
			}
		}
	}()
	return out, nil
}

type client struct {
	Client   // For sessions and Close.
	reqCount int
}

func (c *client) UnauthenticatedEcho(t *testing.T, payload string) (response string) {
	req := &prototest.EchoRequest{
		Payload: payload,
	}
	resp := new(prototest.EchoResponse)
	log.Printf("Client: UnauthenticatedEcho request: %q", req.Payload)
	if err := c.Invoke("Server/UnauthenticatedEcho", req, resp, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.reqCount++
	return resp.Payload
}

func (c *client) Echo(t *testing.T, payload string) (response string) {
	req := &prototest.EchoRequest{
		Payload: payload,
	}
	resp := new(prototest.EchoResponse)
	log.Printf("Client: Echo request: %q", req.Payload)
	if err := c.Invoke("Server/Echo", req, resp, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.reqCount++
	return resp.Payload
}

func (c *client) Count(t *testing.T, start, count int32) {
	req := &prototest.CountRequest{
		Start: start,
		Count: count,
	}
	stream := make(countStream)
	done := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		defer close(done)
		for i := int32(0); ; i++ {
			resp, ok := <-stream
			if !ok {
				if i == count {
					break
				}
				errc <- errors.Errorf("stream closed after receiving %v items, want %v", i, count)
			}
			log.Printf("Client: Count response: %d", resp.Number)
			if got, want := resp.Number, start+int32(i); got != want {
				errc <- errors.Errorf("stream message out of order, got %v want %v", got, want)
			}
		}
		errc <- nil
	}()
	if err := c.Invoke("Server/Count", req, nil, stream, done); err != nil {
		t.Fatal("Count:", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

type countStream chan prototest.CountResponse

func (s countStream) Send(b []byte, done <-chan struct{}) error {
	var e prototest.CountResponse
	if err := pb.Unmarshal(b, &e); err != nil {
		return err
	}
	select {
	case s <- e:
	case <-done:
	}
	return nil
}

func (s countStream) Close() {
	close(s)
}

func (s countStream) Error(err error) {
}

func startClient(port string, user upspin.UserName) {
	cfg := config.SetUserName(config.New(), user)

	userDir := "test"
	if user == joeUser {
		userDir = "joe"
	}
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", userDir))
	if err != nil {
		log.Fatal(err)
	}
	cfg = config.SetFactotum(cfg, f)
	cfg = config.SetValue(cfg, "tlscerts", "testdata/")

	// Try a few times because the server may not be up yet.
	var authClient Client
	for i := 0; i < 10; i++ {
		authClient, err = NewClient(cfg, upspin.NetAddr("localhost:"+port), Secure, upspin.Endpoint{})
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		log.Fatal(err)
	}
	cli = &client{
		Client: authClient,
	}
}

func TestAll(t *testing.T) {
	port := startServer(t)
	startClient(port, joeUser)

	// Inject testing into the server.
	srv.t = t

	// Test authenticated method.
	srv.iteration = 0
	cli.reqCount = 0
	for i := range payloads {
		response := cli.Echo(t, payloads[i])
		if response != payloads[i] {
			t.Errorf("Payload %d: Expected response %q, got %q", i, payloads[i], response)
		}
	}
	if srv.iteration != len(payloads) {
		t.Errorf("Expected server to be on iteration %d, was on %d", len(payloads), srv.iteration)
	}
	if cli.reqCount != srv.iteration {
		t.Errorf("Expected client to be on iteration %d, was on %d", srv.iteration, cli.reqCount)
	}

	// Test authenticated stream.
	cli.Count(t, 0, 5)

	// Test that the client retries authentication properly
	// when the server forgets the auth token.
	srv.iteration = 0
	// Ensure we have an auth token.
	response := cli.Echo(t, payloads[0])
	if response != payloads[0] {
		t.Errorf("Payload %d: Expected response %q, got %q", 0, payloads[0], response)
	}
	// Server forgets all auth tokens.
	sessionCache = cache.NewLRU(100)
	// Try again and it works.
	response = cli.Echo(t, payloads[1])
	if response != payloads[1] {
		t.Errorf("Payload %d: Expected response %q, got %q", 1, payloads[1], response)
	}

	// Test unauthenticated method.
	startClient(port, "unknown@user.com")
	srv.iteration = 0
	cli.reqCount = 0
	for i := range payloads {
		response := cli.UnauthenticatedEcho(t, payloads[i])
		if response != payloads[i] {
			t.Errorf("Payload %d: Expected response %q, got %q", i, payloads[i], response)
		}
	}
	if srv.iteration != len(payloads) {
		t.Errorf("Expected server to be on iteration %d, was on %d", len(payloads), srv.iteration)
	}
	if cli.reqCount != srv.iteration {
		t.Errorf("Expected client to be on iteration %d, was on %d", srv.iteration, cli.reqCount)
	}
}
