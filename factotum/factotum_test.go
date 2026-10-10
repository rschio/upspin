// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factotum

import (
	"path/filepath"
	"testing"

	"upspin.io/upspin"
)

func TestNewFromDir(t *testing.T) {
	const (
		pubKey = "ML-DSA-44\noZ-GfLd9wPCwDg5eW3nSKm2vraRvYL295qqqWyXo1nhQmov6A8YVXuc2nBA9Tm_EyMyJKFDmIKJbQnbuIfGIQPCC4p_6wBIO8XYDbCZ9a1B_4s7Dn6Ms0jjSERkbLlvinrNH2UylgKLgEjSY20TzPCaGkSuBjhC8QUxxr7tM_4v7xUcRpC3ZyN67QLCwM3XON3hzDhrUUlbQHbHgBjHgKDuyOJBQ0sapKSMopG9Ao-AbeVnI4GdC2K297rIPoqFBksouWjiZpsnGM1ZzqP5CHEJM-tnAJBfpw2_wIbjv8w9EQ_bWs_IsFIc0eWyWssGUO-QTRlqo5jLtA9NOQFBu90i3Z_GlqBxuHveNMp8yOF2qIbWLZa2TDODoxVpi84t4SFJ0dQuuC0ecAF0P2_UsJ8dRgDvMOzbAj5Fm0dLHSl1PpOd9euvTLw3wV5Xjd2bSrvOlrQt2e6GjDChrdc1zd4gj0GdkX4UOvZJYyQ6dXYaNsAzv-0CegIjaVCbIHve-vCWd3tR0Kua1tHnuID4Fl_OtoLklPvG9IPsHBTblFMkLp_aZtNciBq3Vw8rW4AxG4E3NmMI5Yu_5ufO3Ez8WstZITPZFjFCDhquxpO9D2QuXRmJfVCoqmmdGTdakcpJw0oPfjs2NBJ-C-aKxQDNOfgpX2eXHF6tuGeHaPe8tJXQ_9mr7i_KKTpwcO804ZWc62l3yvZDptOa-4SUbkLahFuKfpa6BYkW_VIsycjyzREYrSqXiqAsk85IqHEdTwwUkPj7OFfVIXBjx0D2d8BTPMDI06ofjxAWx6z01wtQcXQ6ehT9IwF8UlCbVea4ITcRe3pqPX_RcAxhmuy9UhVltyYrPUynjPxyxkxXAnBQFbPHRkqkUkvpxJtm9X_1dBejkc0p9P-PwJpMdvo2A-RBB37zQrVnLX6wbbND3aQONSobVRuDMNMfZR19XkywDNA4AdxTzvwnl3p7O7Eo0U5pQ7_K_Kd_PPpKysmuXsm6ee1OJZQXFRqYCMqhVB5QHaoK-LvMmP7if7pQKeXxkxMNt21B2l6HbHbZOzB5eJAP3vAMuA1FpljfvKZRaaGGB2GhFGKm_bT9apL2gNxTCy8ZkXF1mR6znBzHrdlx8ZcYE31RFj5gMv0sMasGWenMhwfvj8A8Sv9hrCPwJrEW8Ud6K5HGO--Vresu-VyPJBIpRo6bJDqha9Lf2O8JiGpn8uy9pXXBGZHEq93fVHACqU2q_vMA-yF76HPIdm1riUbTGVeUy-uOLe1UE2FOZ16NPvh3k3GVZOsb8Rz37LYcHXjBa7F-QDMZgL5lez3wQNdKUwC_g7nP0R48EOS_WsG0Zxd-ZJadu2OO50HESNSi5NFMyRiheGG9rxO76TZymlGATwyYpjBSAz403zL79GRYaNYFTN9Dek0xEIgoYeV-fPVhXLinTvaD-Pcw4xAIB6I82egVkM08t1dIycH6XAsLMgytuO4izK7KVdkp5qV5t1_kT-vucT1xcDkxdpkhpDXE1LZtTqYkT6vXZt80cBZqX77LOaJcSpNxoo1Ypkm6u_TsZ_e2i9DJtchvhchraQobDGS6YtJs_MlqhoAG9IM-2BOx4OZjrPs7K0hW31-mWzi5m6hn65Kb8w3RB0TdSJgHOwWJ1GT50pF0e4oFScgFGebV5dT2GMGKSGYBmY-OvFrXB7zRTQXRQjOZfRH7nFowQ4I2lJbqkC6lgtlDMZJOb2_555ztMBcHx24ssqJdeTGIE9g\nmlkem768\ntaZCGZcxYVOqOkG3tymhr9CBsaejiPotg1UAa3IoYoe6yrUMXMg1NLuCC_yz45XIdmKykDtqnMsqbxV8FYKzptmWREcXw_kT3oJX6sjKZ0yLu1qQxJvMfRmcpsKSIBsXgrypD8mH9GKTMqVO4yY9cckCBxBcV-rIdoTCKcl11SOStYGMaGxoyWg1qDQCLHa7HBNgOLKzc-uZVFfFNUC98mtfL8Ic8qlzF1kNbiakozqypYAD5VvBQEZn6MFBwMdDt2a6BfAwO1qvrZhe9JUdQInPkBlExdglVLuXGXOXunSYJkABDZI5MQR16UeBtZONfmau6bY7qFpnTPMteYFGCHlvVOZHlQO_5yi5tnBeVrI569C24qBiQ2pONkq7yRnHhuwWfXJVgowtGLpYwvEQOwo8bNK9SuldhrmorEy6pCR9H8oDpqEmh-hHMFAuM5k4h3l120E0L0o5Xgc95qacr4aeHQUKh0iFyUxWmEO4DwHA1Jq8Xgo5plxcd2MI55Mhp2chAcNCzooj8tNxiHRbxtWI4CoWRRDPFVmjs0dZlCwPLCpQdEHA8nNKeJMg2ply8AYA4Ou2HEIsF9MtI7m6jIJIoQsrodm0kTdiGvKe2yK1FQUOl9JMpwAGCzJGCMMVYuZ4v5FSBIi9DawxQjy_Bpqaz5e-pCcz82UdndUB7jxlAcoDlkIP6oFb1yRIwKXFRjt97fMCzAckAxROsuA0Oekgh9M4JEojFIYkDButoMlqaqlYadI4hHIHMNQ8MXQpSQy1e9WdUASWKIlO7LmjHcFJMcNfLdhmBUqGVVOKJtLHPJknMcGLR_yEYXYCTci4m2ib2DoklaNK2ji1J7syX-QqvrxsF7aYaTsx9UQpRrwUqBqpHJG5efbKeCCCl0TBaKxAjpFfllVftLA7m9US6PvB-JcYgMOWurTGNoZKg8lUxDlShzEpnDXMO8FBIAIxYRWdbGez7hRNAjWYh4E-OwE3qttKCVsFMyCeQdhiWdagR1kuY3IqZRQbvviJoqgECOZ6LBq39qZSipVLwUMTQGzFDcmmJVhDkROtyHqKs9o1ymms0GgxGFCj-IMp-tHCSEtLBOsWODAOjrE-xNWl1OGkgJm27IprNxSloboPSFRuL7oN5bOHLfeT0FguKBRQPlV8wuWkeRck_qa8eyMHA6qY2gqX6Mp3fPG1uGxwyBdJftkfa9y37eAfCIES9kZrpZioSGClV8lftrRlWhLHjkNBskkGFcxEH1MpfsWTOIIugOJLorie0HuGO3WZRpewD3lm5alRs_SqKvQPM2J0L5pwmIAnYQRo1VhFE2JN3XoHBJedGdTIVeS4m6NJz5EzAxUTb9aZUxAiMrMc0ohJlxInb9m404op1HQKIRe1mFeHuuWAbnt7clbEooCqyyNd_2msZiwMZmzNwVhRlMkbIvoDqHcYUPwO_HHOPRFy_GeBSoY30SUTiPC-sXpIg3w4RcTDqlQCCPtb25cFyZmIzbiKbIGndBahGJlGrdqXVRiP-3IU1PDGk0a_DALA5KJ97jNxrkkxTjVAEW43ZH-ESxcEDw44DQARCYxhiHJxFck\n"
		secKey = "ML-DSA-44\nUqwgllDelrQbKFCg4z3_bPa3FY1FGR5Uj3BcMIWj4ug\nmlkem768\nBM67dEb_UG5G3AqielpJ-U-qCKTBWL3qlq9e-bHVK6jObSyZKwjqBVBxlwJ3sM1wLcIREdxErFSu_8jsRmN8mA\n"

		newPubKey = "ML-DSA-44\n0DHDGQJTI8ZcZbxrv-kWNQIqMqYOylGLiyaGNZY2uHxyQ6vOZ6QThI9pSPSRsQsO9rLC9Zal14C6qicUZ_O8wBSgDUOWLS3xMx-koX11PMNMJ1Off9xemp6kzEL4N0Etf6btYwoqt5veCNW1kuJLVTS6HH25Ks5P8L2H5a2F9xT1_YaLS99Ma72tJf-pkNoYqhXyFgGdjlhaTPtBbX7AlomTMHImI3MA1qeBqNBKi4lIH6K3Uib0o9LpoD0YjmfH9cdGyzAyzQOlL7zXlxAwznczQYVd-1q-xgs2fcykFpiTgRQMCn_effuNy16bVzgH5pgApiKFP1fNcHWPPkBJbhV8dyooiMpSA-120_Y1V78V42Ll46CO3UCZM45tXOQOIKZ13tHNwDH6bLdcYRdwSxcczIFF08lhHpbEFi_Qg0BUzNyNBjIBDgCEa5Rj5UirTd6Ar4qhkwZrAXKK83iG-VQZwCtMmy8o6_CcvfFgGxdbb7kggWhE_7-S9EXow8o0yjDmfmZGjv_U2OwlklDshhglSorZp2oYw0O18Fs0KNvINkeeLvlMe6k0jP7HtBRU9ZMtPXwqhoQCFBO5KGVwUrY-wOJZysCjckth6mzSGf9Wk5trmHy9c93GiAYVGkkZWf52dC4M-YFyvPBO_u8KK4ZSoEL9dox_1Q1qTV8Yb2PTOLK7nCHOjismZtsLJK2OgG8sfk9EllN_nqtsNopQMH-qc6Al5pCsBakKvOrZny10vsyVs-2vslnF7T4_c4KOuV06J7MDis6tcJVfalvJybCUy_GFZC4gWLvbvtXyLc9i4dRKiyhqWh7se5-pTeUR48lMmIJFstUiyPfM3yHyyGIWNua-nqO-WiE6BaiYdVuPA4aleSt-5ccufsmV5c6gaJ-N8gbzjExGhE3EVSa3cTCn5ZBkJT2I2gBeRL_aKJrb2hx2vMlBe8vjeBHlg6saW9Zv9oKGhCqzffWAUNKJmSpgmRBEBU5YgPzNKLIq7chh6L4qdzNKfjtqQVBLce-PSHTKfH55XmbDyx5D-eInUPMc0Trm-KvyS-45PnqErCclC8ipqsYHjWy_rVVgwSRq4lS33EBqEC1xYmLen7zn-irDLF80IkuclqUqXzlNltbO8GDIK1-PZRjLxKw_NRR_j-9OLZwhcvF2NWUzhuvmqcrwWE9r6cuDdUzKOlqf8ohOl0PgqNRPNKamwBkhrhz3Ir7ipaTeIWaYpkXEWr4ytnj_GaJ3uB-6Etx1aJxsMGQxYewDJcs4c01B0W1IpYL-QlAxZZpOuGLZz3CuwYPSK33l3jEDcO9wI4fZS7OmFaQzor_VGwywfzsGkTfCL76iaMicsTtJVCUcGCt0MbuIun3QdNQV9-SYy03WEB8wD7_3gP_s4-jKmn6FuRxqTaNFSThQ90HZm4TGx5TMNtWqtsht2jMo4NnMAWxTswuBB-P7lWjWkpaCNDE7tuqxsCmfaSuXhycmVO-Bk1HwZ0TRRYNK4cp71zMMZektwSJUWonz5JY24ISEaeskunEJ7zR6-nJ3EXxSvJB5Ok9T6rRMpsvguZNwDYvKCU1gIFNLmPnjNHIjA97Nk9PHGn7LIbOWXdt2fLLilBVOHzano9XYXRh5vuRsB8xIKWyVXoUDsobauNn91GSIXwZS-4drjJ630MfCQhDQ4kZPIMoiEdKjt0Qr1TtC2o6-XcO-FEIGD0WlpSGgTqPGb4BOQ2aKl0BChDdOQS82T7ImMeBz_VpOjA\nmlkem768\nRkgEyDdmx-dzoiGbDSIOJGSUAB2tWLObd5Gi8NcSIdhfsiWPaAK6a_DOBfegnlfAoxAFzxdiwgGuEBtdwUxTvfiWThtT5Ymhzcobo0Oca0cMKHR8rjFpShOVH-wpM_h4-vl0Bxi8PxjABTSUPoxlW2mlOiZ7vsCfsNM31eBLR-lnayI_CueRtxG9feB2F6wYAqa5UgiEElyinarJJagLB6mQVbSxHAA23hALbAyByNRl6xcukURJ7gnIBQCyKQij3Rpzdfwl0Xs752VF0wNDCboV2_LP5wsz4cec2auALGFSxreNfHsUxKowifNmIiZ3jiYbosI-VoaWvxMfJUFsZDE7laVysvcyn0ca7dAQUdd2PYR97ERWQ_AJvkE1EJAu5kC8jVGleEOOM3Bw4HHBXaeB8kFTVWV3KDZ1xzNBgFg4OFo8R5ytiKA03HKhWQQhDpiodlt0M7ZaQgYf9lh_xZOzalKiqyIIRTgUAKW9RcOjkMdQtLkCyxCK8HQdVbOgIGFEZrNWrKB5CuJQUTBAEDJOcsVTDIo9j4ybklqspBjKsfVvdUoIPvyyDBeBtPaEjAsJN1pGtaJ_Dgxx7gygYTa6sIQZuKpMRgGK5Os1XmR84jIlFXkROih_bdtjy7gdFuc-upETDqF7_RRLizhl6JTLlgQriAUVhVNR68u_3uyC0cuE-waGHYmYjxazbbNBM0oRdgxHzVsuCJI7lGRNCyKLJ-WXmZIWZvskTnZkNZuGCuWRkGBY5uasaAXOEfBz2RewvDtUKAazLFodQZsfcjOGPtYfI0fH1XUmMKKR3hsgcDdhQiMsmxJteWY3hWx2liiCCrkTAiiY34YQmNkr-dpIkQEcYUWtcAuI5qCpJEW0Vcwx6laXk0BFtjCyWjafbZy3DSTMA2G6CgoddiBDq9KGZ1wBbbKGOEh-AqoGT5yvpfxyx6mqkWlyGXat3cjO2BckX2aD1YpV-TkVfNmA90dt7NRuUJaMeIyWnKpgXdN2qtmnwbmEZmsZ36Y6flHPy_gNNeU4_fhCAYVHLqQBdlcWteJdUhUGLBENW7Is7NieyxEp56iqpKejOsNHlaUk5uIIOJO28LZMyvtwaJsbpaJWy4YFmyZ3ktwgloWyeACGLWo0y3SvOdInfqI9ZrtkaAR8FToI4Rm5e4otgiIqJsjDgwqDPNK6UJqdHVwotXg5UXi6d8OdvziE_JNB20ZscdPPonYWbbuHLUmyrBcC8GyRBJTHByJBv4MOekhoD3w319EermSgu0oiQXDJisRWo-C8E6MXJwHHg6pJYEyvGIqwgLtrRQOaMNMGrgmW7DJxy1VaKClypoBX0VNSk8WbXREQDaiTEBbK-Etc7fCnhVJNTLIBATqLcGVZQsy0B9ivraR4t-s5W4kJTElpO4u04pgsYFTKm3FlIbcV4QeV-uE68odGzGkKqvOyg0CLV0wkaAqJCTVNZlq_60oL1wEwFadwfFhprmYTbhJC3KgwTvYVQaYHxSFjA1BminVY4-UbshFN0ZMAvZK0ZPRAV9RipTwvcs11NU-0juZuZaGo7Ng4JSFc6K20lJ7EA9ZQhlE\n"
		newSecKey = "ML-DSA-44\nuV942FFD5DAENIcwedg8dCqc4spvrmOrUd0lXNYUs0o\nmlkem768\npVsOCp_ibux_ueP1ltZh9Ibl-ITY2xLARfzuPO3TK6AzW32aLkZZJucill1GvwotkWWgkrx2LA71VSeI6YVuJg\n"
	)

	cases := []struct {
		dir        string
		ok         bool
		public     upspin.PublicKey
		secret     string
		prevPublic upspin.PublicKey
		prevSecret string
	}{
		// Check that basic key parsing and parsing of archived keys works.
		{"ok", true, pubKey, secKey, "", ""},
		{"ok-archived", true, newPubKey, newSecKey, pubKey, secKey},
		// When we fail to parse the archived keys
		// we should see the current key as the previous key.
		{"bad-archived", true, newPubKey, newSecKey, newPubKey, newSecKey},
		// These should outright fail.
		{"bad", false, "", "", "", ""},
		{"empty", false, "", "", "", ""},
	}
	for _, c := range cases {
		fi, err := NewFromDir(filepath.Join("testdata", c.dir))
		if err != nil {
			if c.ok {
				t.Errorf("NewFromDir(%q): %v", c.dir, err)
			}
			continue
		}
		if !c.ok {
			t.Errorf("NewFromDir(%q) returned nil error, expected error", c.dir)
			continue
		}
		f := fi.(*factotum)
		if got, want := f.keys[f.current].public, c.public; got != want {
			t.Errorf("NewFromDir(%q): got public key %q, want %q", c.dir, got, want)
		}
		if got, want := f.keys[f.current].private, c.secret; got != want {
			t.Errorf("NewFromDir(%q): got secret key %q, want %q", c.dir, got, want)
		}
		if c.prevPublic == "" {
			if f.current != f.previous {
				t.Errorf("NewFromDir(%q): expected no previous key, got %s", c.dir, f.previous)
			}
			continue
		}
		if got, want := f.keys[f.previous].public, c.prevPublic; got != want {
			t.Errorf("NewFromDir(%q): got previous public key %q, want %q", c.dir, got, want)
		}
		if got, want := f.keys[f.previous].private, c.prevSecret; got != want {
			t.Errorf("NewFromDir(%q): got previous secret key %q, want %q", c.dir, got, want)
		}
	}
}

//func TestClean(t *testing.T) {
//	f, err := NewFromDir(filepath.Join("testdata", "ok"))
//	if err != nil {
//		t.Errorf("NewFromDir(testdata/ok): %v", err)
//	}
//	fi1 := f.(*factotum)
//	f, err = NewFromDir(filepath.Join("testdata", "comment"))
//	if err != nil {
//		t.Errorf("NewFromDir(testdata/comment): %v", err)
//	}
//	fi2 := f.(*factotum)
//	d1 := fi1.keys[fi1.current].ecdsaKeyPair.D
//	d2 := fi2.keys[fi2.current].ecdsaKeyPair.D
//	if d1.Cmp(d2) != 0 {
//		t.Errorf("NewFromDir: comment improperly affected key")
//	}
//
//}

func TestSign(t *testing.T) {
	fi, err := NewFromDir(filepath.Join("testdata", "ok"))
	if err != nil {
		t.Errorf("NewFromDir(testdata/ok): %v", err)
	}

	data := []byte("this should be signed")
	sig, err := fi.Sign(data)
	if err != nil {
		t.Errorf("NewFromDir(testdata/ok): %v", err)
	}

	if err := Verify(data, sig, fi.PublicKey()); err != nil {
		t.Errorf("NewFromDir(testdata/ok): Verify: %v", err)
	}
}
