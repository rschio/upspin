// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"testing"

	"upspin.io/bind"
	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/pack"
	"upspin.io/pack/ee"
	"upspin.io/pack/internal/packtest"
	"upspin.io/test/testfixtures"
	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

const (
	packing = upspin.EEPack
)

func TestRegister(t *testing.T) {
	p := pack.Lookup(upspin.EEPack)
	if p == nil {
		t.Fatal("Lookup failed")
	}
	if p.Packing() != upspin.EEPack {
		t.Fatalf("expected EEPack, got %q", p)
	}
}

// packBlob packs text according to the parameters and returns the cipher.
func packBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, d *upspin.DirEntry, text []byte) []byte {
	d.Packing = packer.Packing()
	bp, err := packer.Pack(cfg, d)
	if err != nil {
		t.Fatal("packBlob:", err)
	}
	cipher, err := bp.Pack(text)
	if err != nil {
		t.Fatal("packBlob:", err)
	}
	bp.SetLocation(upspin.Location{Reference: "dummy"})
	if err := bp.Close(); err != nil {
		t.Fatal("packBlob:", err)
	}
	return cipher
}

// unpackBlob unpacks cipher according to the parameters and returns the plain text.
func unpackBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, d *upspin.DirEntry, cipher []byte) []byte {
	bp, err := packer.Unpack(cfg, d)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	if _, ok := bp.NextBlock(); !ok {
		t.Fatal("unpackBlob: no next block")
	}
	text, err := bp.Unpack(cipher)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	return text
}

func testPackAndUnpack(t *testing.T, cfg upspin.Config, packer upspin.Packer, name upspin.PathName, text []byte) {
	// First pack.
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
	}
	cipher := packBlob(t, cfg, packer, d, text)

	// Now unpack.
	clear := unpackBlob(t, cfg, packer, d, cipher)

	if !bytes.Equal(text, clear) {
		t.Errorf("text: expected %q; got %q", text, clear)
	}
	if d.SignedName != d.Name {
		t.Errorf("SignedName: expected %q; got %q", d.Name, d.SignedName)
	}
}

func testPackNameAndUnpack(t *testing.T, cfg upspin.Config, packer upspin.Packer, name, newName upspin.PathName, text []byte) {
	// First pack.
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
	}
	cipher := packBlob(t, cfg, packer, d, text)

	// Name to newName.
	if err := packer.Name(cfg, d, newName); err != nil {
		t.Errorf("Name failed: %s", err)
	}
	if d.Name != newName {
		t.Errorf("Name failed to set the name")
	}

	// Now unpack.
	clear := unpackBlob(t, cfg, packer, d, cipher)

	if !bytes.Equal(text, clear) {
		t.Errorf("text: expected %q; got %q", text, clear)
	}
}

func TestPack256(t *testing.T) {
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file/of/user.256")
		text                 = "this is some text 256"
	)
	cfg, packer := setup(user)
	testPackAndUnpack(t, cfg, packer, name, []byte(text))
}

func TestName256(t *testing.T) {
	const (
		user    upspin.UserName = "joe@upspin.io"
		name                    = upspin.PathName(user + "/file/of/user.256")
		newName                 = upspin.PathName(user + "/file/of/user.256.2")
		text                    = "this is some text 256"
	)
	cfg, packer := setup(user)
	testPackNameAndUnpack(t, cfg, packer, name, newName, []byte(text))
}

func benchmarkPack(b *testing.B, curveName string, fileSize int, unpack bool) {
	b.SetBytes(int64(fileSize))
	const user upspin.UserName = "joe@upspin.io"
	data := make([]byte, fileSize)
	n, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	if n != fileSize {
		b.Fatalf("Not enough random bytes read: %d", n)
	}
	data = data[:n]
	name := upspin.PathName(fmt.Sprintf("%s/file/of/user.%d", user, packing))
	cfg, packer := setup(user)
	for i := 0; i < b.N; i++ {
		d := &upspin.DirEntry{
			Name:       name,
			SignedName: name,
			Writer:     cfg.UserName(),
			Packing:    packer.Packing(),
		}
		bp, err := packer.Pack(cfg, d)
		if err != nil {
			b.Fatal(err)
		}
		cipher, err := bp.Pack(data)
		if err != nil {
			b.Fatal(err)
		}
		bp.SetLocation(upspin.Location{Reference: "dummy"})
		if err := bp.Close(); err != nil {
			b.Fatal(err)
		}
		if !unpack {
			continue
		}
		bu, err := packer.Unpack(cfg, d)
		if err != nil {
			b.Fatal(err)
		}
		if _, ok := bu.NextBlock(); !ok {
			b.Fatal("no next block")
		}
		clear, err := bu.Unpack(cipher)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(clear, data) {
			b.Fatal("cleartext mismatch")
		}
	}
}

const unpack = true

func BenchmarkPack256_1byte(b *testing.B)  { benchmarkPack(b, "p256", 1, !unpack) }
func BenchmarkPack256_1kbyte(b *testing.B) { benchmarkPack(b, "p256", 1024, !unpack) }
func BenchmarkPack256_1Mbyte(b *testing.B) { benchmarkPack(b, "p256", 1024*1024, !unpack) }

func BenchmarkPackUnpack256_1byte(b *testing.B)  { benchmarkPack(b, "p256", 1, unpack) }
func BenchmarkPackUnpack256_1kbyte(b *testing.B) { benchmarkPack(b, "p256", 1024, unpack) }
func BenchmarkPackUnpack256_1Mbyte(b *testing.B) {
	benchmarkPack(b, "p256", 1024*1024, unpack)
}

// shareBlob updates the packdata of a blob such that the public keys given are readers of the blob.
func shareBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, readers []upspin.PublicKey, packdata *[]byte) {
	pd := make([]*[]byte, 1)
	pd[0] = packdata
	packer.Share(cfg, readers, pd)
}

func TestSharing(t *testing.T) {
	// TODO This could be cleaned up to be more like TestCountersign.
	// joe@google.com is the owner of a file that is shared with bob@foo.com.
	const (
		joesUserName   upspin.UserName = "joe@upspin.io"
		pathName                       = upspin.PathName(joesUserName + "/secret_file_shared_with_bob")
		bobsUserName   upspin.UserName = "bob@upspin.io"
		carlasUserName upspin.UserName = "carla@baz.edu"
		text                           = "bob, here's the secret file. Sincerely, The Joe."
	)
	joePublic := upspin.PublicKey("ML-DSA-44\nJOsTOS1f3Yx58d7_7RVRsh_jwQGPoJi3QQUN2lyauDiPPwq260pDOKhSfiTNVaxrzdF_avivG1mXxihhWo9uQJVwhWBe_6Fj9taudOF7hgFJOkGBgZeiUGK4_TpH68zTZdBjF4seiIC_Nu3Oc-Ie1UjJG_iHLnGhGiP-xVKWEc9yCuc73mg5Xtwr0rqQAZcZeJjFsKqawC7rIYcb3i_HqfDQQL3qOCBLrAdf3yJCgFB11_m2rKHpty7jwPZweIoRqexXIkx9CFA3UOlu1QiH5EJqUEyqfqK1BdP77ydODiGRDTEBqD0tMAgAmece-7sbYH3CkmjedguGL6djkzriMT-pRX3hTQyYLkWlJqobARUoPyAsQVp3eKIb19TD-RIKLX1vi-kCQ23lUu-M_iDvzTmyyZX0AsbACNk5b5h27_UeQiqHW7x2jQpLEf95a_bEnXoxZx6SvPHLz1D5eXQL9lEg3uiyaX-CIat06Gegt1_tYJEsCGVoyx8yolemNLonhfkUv7wJwZ9H2KJkHzCQbv_5kE6rZe0WvE73LPYy_PysmxWZczP1Vjov9wNN2cTbw19S5IcI0G8Hd3dAVabOT2GQz2yadd8kl8RS8gnKEqn0Jc7ZALDAfCx-1Z4cPUJXXUTeOiAi839Gum1aqoJ3Ue1G5FBpPDWTwEEf5FfiMOnOnQm599N32MURXCnVpiut_y0EFoQeLyucxNK96xdodzbHzoSm3U69ZSDPlw9ZwoAojIMG3XsVqQ5wQl9HPo4vZseodHaCHr0wYCNwI9eIWwj9xmPRyqmvD5UWsc-_3ywOtc8vQXGij1sCYrcgS8htiwKswDyu8HmUJb7GwBVr8FDd2KjEZ0-I5uzJkQ1HqmJ86mFOJKyPZNnQlsh94obyqESu9sbj0hmNH6-jP5YsxRN357mBqkG0mWSsr2-r44k0yDVjMsjm0y1_-vnqznoSaPGkmpMkynQs8-a0weevT_1CERIyDpuVH5QP6gRIscFM5d2WTwRVi9_EbZKLpNuz2NBPF_i_674mCCvS-4M1CrNTQVPKVRaLg4UqAk5EOYz6Pw43n7JtSp_LjIt-_LvH0po2h6NqbXod5oheDi9faFYb-5tBAfLlEyGgihGjtkum7594jg8FQHNcqdxmONoxoZ5VY4gNgeLGNnaplvVGspTjd_ollw3mzazVGOlbU1vpxnD0bGWAU4UKC9BZpKhkqVTegYIkPBHCgigSCclvEeySHCm0q67Kx2Wa-5LvZGPo4gSn6_n6OALYQOp9nTQZcicnOtj49pk1ZppAGDFR58S6pjBa_X8UI9ryOhG6gS3hVfvzzQBWn1RG7XtbKlou9FIAWX6Bjbw_nYRw4kfa-Q1pfVEAmzmFV60IjO2UhEB_KRy92TLs2bjo0awfSpSam-L9IJ02hTmh_dbrlkYG6QancpZOKeTzdItWk42WTo_x6YjC2wQkc_ted_9e6NSicAgbAtOYCenJr6h8zhIQmrXC8Gtn3juzwBbq9N6IMhT-NcakRN8pMF9XxNkqO4j16qwvrjD1F1wnFOTT95UDHOpoYs7WHTV_ODgM3EdbCc9g0ou5krgtJJa_Jd62719ygQYdPfGo5BqWiLC6aK-cOkmre7220F4nRo-MgykYC4OAXUGCs8zib0GppoSAfmmOOeK89sMKPN87CUMtU6pfK728j2eUQC_OafpEGp9BnpHeY_9JaxjoZ94QXcl8isShIMBon322HfbZlG9Z0cmS7g\nmlkem768\ncYg3c2i9X4V8D9cIF5JqlHSAnZsSalMhzeur0SkmgBJzAoAQ79gsK2s51XwTl2FozPQIkdq4JkOpSDSe5cY7ezOWi9a8x1AFkElmfdmEP5pZn_azPqZL1IN8tWFaZSV9bSLFKRszLMSA8IZ5xrUZl8IB4VSSBQGxUQo4igpKnrO_lqktUoOcVIZ_o0JRq_fCC9KFG8s9XFM3ZGFTL9M6FSXEOmlMuBSANwgGH1Csr4jBojmwmrhU5nSHKxmedYONtvaDiJYPV-nOYvCj6EV2N7aXJmSjSvNBSmdmS_pRkIJoBqe8QjJtLHl5UfsJgOWXv4W8pfukyTitFfpntnQMJ-Ku7KwF58YkKTOh7eSL9Vs__rO8YKIJr1NTu-i-q9hOJTIXkjST_GZxteCEAkB8H_o4oPtsmjy3q1LKoJav7frG76UR4VCmCqNmelyGGYO9hlFVfgmghaud-JAgwPgH4ftp8fYz8OiQ5jsEYeXE9mkzhNqa8DkKaBxs8UK0KdqVkTE_5cdmulmDZJnLGHtDb2C5xtq1f_VYPCR85oVZoMQjTBm707oErpnGSGq-DGewllvJtSKYUqazjbsFQYiGGyA0APcvY2hTaGx7P0eq9psy99ZnGHxUrGF-7oR74OCsyiyyrXkvStA20gLPUgKQ3ys2bYY5_xGFdDAR0OjBiOvPchRX_xDHG9gydOCetxGgeunBH7YW5Te4q_qxCohVjMZVYlqxYaxvy4IYM2uuzoI_kspTPxvF4qYVZHuWpTCLReVbD8gDmZy4Q7OIb7lTnJhXr9SnuYHF7_Oee7RlvBajhJo_t9NkPLPPoQgdKkVlcoQLDJU6i4RbgZxQlcFkuRRUnqwNORQNG-Ojk4uDdUIMfsqV0yIB6YHPTPWMUjeEHxENxNoxj8eZbcAvqIhyQWjPekN8vORk3Cga5ft0w9JGA8EeNBBpGOKxOZIfjkweBeMkxNIU9JQq4YpcvRoLA8e3OrA7XEcBwjluRsQjJJZ_O1VrMicdEMwKojVpg-VceYEZfgq5LBO3yeYbuPlI08t2uBggEKEaGYAeP5K2QImSLrSPF6Z64YetVoOC7nygOQkbb4wwSce6GjBUqala78Oxz4nNFUk_SDoiQGhQVVWLJ6GAgNKQCDCao-VgtRd_b9xk8Vp3T4Wc7-tJqnSi7te0THBNvMIfVQbO3frKXZJQQ5gyx6eWUcJK9wcfs6EYTVgizIbEpxYy8lJLcnhcaCoE_ywd4UEjKlJJtadJHXZ89BCjXDNQ9-QFkfycDcuDlFS8t1tBkpwp-HoclJQ71_c49TpmlGVsA9BbZtCvysg2Wot2bbVXU3UjyjKTeroUejkyyBiaAqtXEPLAdHUdnpgRhXbIM2xkg0ctqFJv7sq6X9C1PmTI79A4EVGpLYgxLUMCFkkF8Lq-_Btlv2zNPcFqU-MTsJeaQlucwGKq7BF3YZcdEWdb1pOrvsVaOvaR3WYuMpeW8cyIcsNbhhCOT3JzxFV5ChQbVEwVw0NUaxUPKrd688Or8dFNJeWawNsvYd7UOjyxvMurR5482nwi6_3t64OU_6tvbxS1BXJ3EuU\n")
	bobPublic := upspin.PublicKey("ML-DSA-44\nGRlDG3kpNAvNdUV8G6cGAD-OSvPGwKsIgR0gGEKsQnZjpdJ6Kge-JxO0yoHQWgJsokF0-7DA7nIs8SOGbph1dbtuNB4cdyAZ7jJV0y2kwIdXnyKpnrv6IFgG1XKOiqiK_pUnp5yGFT0XQCVfQIe4zOMjyRgodTsnfqaIJwkOp6zjjvVGumNGk800ItXvaSCKqI2t0DrlFQeBIf-i-5ZYNicoNTCknalnax5ozKhxb6AzABZqjNcLP6VHTPuIRMDj0hAgLS-R7Y5LS_4rJN2Isit1tfawPVC9n26ZivHaO8lU8jdMWme3upuJ29pOHzpzVQXghcy3xsjWPK1kjcLGQT1aotKUC_msYrdUDw3MNfLlI5TqQWYPII33Xm3PIwb4ogKov7PA2G8yW1IZBxNhQTWqz1uvvnvHg85rYs4d5SyCQPMwZD5jsdhxZfIiaXhCc73XW2YnisJlGMifUgAvREe_CAH5NhAgT4FwfWaoduJ_Ofq_A5cyK94DLsbSOxZ9RqVMs1cCsXO5T6rhkSiU_NgQvlsQV6bqOvKhf2Ef-2qP359fZtHROmAq7sjfPKBWnY87OqGfprpJ1E6iRP4mi1eRmVZeHUBIR3TNeLPQPB1UZ9QEA1T2-RMiJlcs0DSmZ7LEZKeM5T8fCOtc1gO5m-4SjGQ1JKmzC5NU0zXx8Ijpn0mZL8DtxSzF_dB3k4l5xYJi-Cu_QlULl0p9wsS_boP6VcMxsTSyJq46C4N-_tr3TCv6wHt7YmE8bms9V6y_kyzaSdf9iioQjueRtdv8T-W3zzqQZSQ8JhA9H0YGqVZlR89SMLUp9YB9_Y0Ifu2bSuKMzl7HlpvVPoBaMTU2s4GIlAxIuegwaLWGczrfgu_V4_6qmiQ7pH7hl9LL04hcK749DH9o3yM4zZacaTkiWJ4rETKh--ytSu5oP3NcvoLZsSDZSkKE-RVRvw-tDhQcZhlYbXEX0rcVyAVYpfd6dYXShqzWNNLrGrErIj_9ymF1FQKiqBVsv20RSkkVq6R9W8dZJC6L65-27D4oVXVelrjAH-KCcjdP9Mx7ZnL0lUvhyz3WgLIShdE6bg86Xuv_oIVmEnvcLZr4iC2qJXLFyUi3tepTlFOgkYj2e_UjvnXAqW5hbAWQXmusYkGYQIKp1h0ZRayjbrM9YdySMvJ-R4UVEbybP1u4sJ1v-xyuvtebxy0K7O8Rq7y0oUWov5Z1V_B1vvWaJDBXSTCp1KfP1TA6FxeN2F5a8cA-aEMZ6Euc6h-lJdLRN_dge9uBwhlyB_7jLBP3nVLFQ-Qi2qvvBfVy6YbFQ13XxOEIsItoW8nVa8vZ0le0Rho1Jgf9yebWdv2Xptxr1fpXAb4JmSABV2_hBWinDuz9Z4wVMCRm__1yF1gbU5gmUJsXfv5K0P73nMTPJrVXVnwAYnNgodJcDaBuGElq0nRKicZEMbzJ4ucdAV_reMw2MZXFxq2SBu_zdCrvWhHbpOBFhXmyBMPwWBmZSRaX99MeMW36Pa2aDWvQoJRiAE3bgBD9hoUMZwQBqiVJ4GjSUmVctj39leyAuk341uA-Zv_608Y1q25efC120e3UGIlBcMAuftASrHX5cHgpFGPDR9IfmA9W_3IE9dQM2BJ82PVInMbXjfv02l9IAHTf_APrwy9ThpxNhZYmwRPVbLQaN9QyPLhrOqXGKbpyLx2ra31Ey0KQW6o80gv17Ge6qIncbtFCA44Ki--vT8VdoVMt4chNld--piXVrQ\nmlkem768\ni3abLOENTAFP2LmQa3TDO_R1e9adcsunU8dfULWRuEMn3uyFSyMK43QwZ-Gm-5ZHvJWaqRNwPoIDtJMR_jYVCoBu8Eek0zsFjVSuaKeg0-YKiIOvIKcAewtAp5fApZcL89miGwCLAit95hxa9lmDenCgE5FG1PwERRtC82Kce4pv0gmjU-CrtKmc5bwYhuOvbci6HakCVBmaESRAuOZVz2FKZ7q4KoF_e5gew6xthceZmMpUc7Yj42Qv-TYPXnJtwOSG3rCKoSgy3spA2zJkcsg7NeuVeiQf87VoWBwDL2p-grGeaYahDNLGO3pxZ7sSa4t8foJAV0AKaLqvLjppaxy9rcsBnwIT3GkAI6pcb0uSj_YlavO4C2l_7hdQwPKaxYqm8ilWWWsF9Pu5EFu8Bbuv1ghLKmc9JKem4mObvyBRS7EW8TpoRQoffynLtvizLikZLoEjrHGgkUUs0xpChGpk2RqUeAxxQMFvaVetobV6Wzpx2JmrI3FCqQjAUCiGlgCKWCs1_-uFFym1IMlaihpS7MUe0GqEtnq_eVYfClU1GncbONiEF_iQ7YiUlqbCFzxDKOeJy1O30TqZQqUeGnCEh1G9zeekxRwS7qSUujoYKWSjs_d72Dye5jMj5DHJf3ZM-zc4aGZX0-WkfqgEWRhipKnGFxmGE5A0LcG7QXUu_mtuLMMul6djb2xHD0pOC6MBtNWysoQtE7kB3DQsU5eRhyYzRLkLZoyUrNR1WAOqY3FNVZtgrLhJ_jkFOzNZHSzB0Di0v9WCjhSSUjMzESVhleVxlDx3GRTA-EGIvjVYL6OJk4HMUvOoGPM25IO_YddpKSAlLVwO-XJ6D3qg8DxvVWLP4SK_pbdhgtVhphh0EHs5rUdmWQRuuOQThGmE65Nk1ktFw_WhdRdqEitWksW-Bhay5AGM3jw6GyNAm3A421a3mOAbsVKzg9xg32JyWEARPcWYLyJFuTdhzvajuBMY0Lu7WeFit4bIwmKBRme4C6ofTOGNqXqoi8tWDmIzBYutY6E3d0aCpvGL4nySYyCzDSGZ2DBA0uauMyhfTWiMU4Jtiws60aEestko9GYJoYIPHfIjmjDNeUAwgFvEIIHFMLkA8Aks8ZQJdOlcwwYoIiMHXGcyB1J8_WRqjSmcjbiGEeU29GczwxAkC7p_cQjLluhTqORM--CIkqFmSiOysLpCQslXkyG1NeQBP8sLHKErUsJAkbBABUgZQnSE1GUl-MuOoPsEeJx3upZw2Kh5BBFTTFYi1Pego_ya4LVk2_WAkSxeiGhdeaLAEbSnyTlIkySnopdvOutgXrfJvjfB1byWcrYnOkxbkAgxbFBAwJwgNpgyHWDO8TeEqhZxvGm8gPgHnCl_1oWB30GUsCks44cAkTImROKXu6IU60KcR2BFgwO1AOU0TKPKVKmB1HSzF9atSSa95KoF6aYOX6FZBFclTcSukzeFPtAMPKykcPlqYGrDYnAZuJa37fwPE5iTo9M7L3O-bFoQKXpVoBalDMsgItKlNbm-3dpJRFBaNxX0FjXjsvCyb_loyrVOl9nxyac56EQ22WPTalw5Md8\n")
	carlaPublic := upspin.PublicKey("ML-DSA-44\n_kAogGKcBQugwtMMIRE0eZcIYRVZtQtQi8ME2uInun2GXJj5ZRTNEWFSRSywDhc5D6jcIybWvygvSDXgu5IEZL8DADUjmQ31X-9UKabdRpUn2mbqB-A7p5XqQlEyb2dpFQAHm8HfK5FKkT-b7Ya2GXIIb9oQ_vjZ2a1RR_Ei_qD2tXHLh86NR3UKQsC2s9W4iydKAjsxyXwgoEOKKr52lf74sSvfEp8Xw1Uy7bnuom1Ap92WWb25UU2PRkJZDNhjt-yEKU1hCEU7zjbKpwH_69p_UCiHJuxPfyyfKgaFgt7GsmD5Q3P1FbLer0dySqWuVAWc55vHtyv2bU-yY-ptXE-2h4xA_em6TsX0HyLYpu2OEqEdhTWheSvDIn0NEP7mB_Nfe285kLipi65weHU40-ElqOZxPX-yx_qeeCbhCHthanIgq6vgGKKbqoMQqsr0IX6k8OIF1q6GihUUQBQ7a9MVRSu6D6L1c8NaVp-xghh2TJVHWkODOpldVHIJYrsKwYddXoYriD3y6PuU8rE6hmBnZ6vUPdQ8QXOAMInHMMpPPJVHk3UfcXpve9yz1ZIfslrzO9DA4POH_o4E8t89SHuPFCOCHB0fwyBGVUYNnAP-OKfh6vfrFy9oK0PnOzHgCCaspeUNO-aYtD1nslnsFnI6D9xsQybThJQkHNkIYqHwceEJ48NqQeMu3GhOSKTOSVrhH9c5-KP0P98gX8GGSDpvlFx6uNlbL54Br0noT_2r7bLhoBbgtEGN94McLvjxwdNy6bwfSLCkhMtu4yRoMPn0nidTFRWy6b64VReKyFHQ5jnqpieJcmGzS65QXguHDE4Z1sulAkLujEqrp5ZfbAIc605zETMJvf9sIiVBwLbiKp7QYnkKf6G6Jray0O86EpKbvbWCc-42L2BU86RbMsUy_6L1hBxYN1AFBveqLTwGertEfReL1p9NSdHxqwW9J56-Jo9_DEUgECXlBAOITXgUn4-Q3UUuPpqDEINzWsZqMvuQWyG4qAIBrKFwNK3gSfB4Cd9FVWW-f_1ETTzpYXY7hAHfoQUwkKCqfkBgAopoLMKY--aso5VSp7C2GHKZgLRqOni4wECwoqZ-sxfRQVIvliqZqNGchApr2fnMfjoIJ3zWDwS-q8BDzE0mFzMH5co7ARGVGSzTCn-48i0WfXbXvQ_Zo4EdKdbQiFqBjB0r13eMg0WyRXrGW3j9pJKtyeAR3EiH9ydZVdrRb1mJKn9wqMm9jmxw9FfUKPTKTs1thvANZ7Z03m6CuxCRJcnvrz8hZgXnli4I4rug_7Ya6avXoWtfQNb-Cu3cnB556jtAP1YVmG6yeHk10DBu6Wc8pwgKSqKTlOPkYOXcEspX220cc1k-AjCIbDxwdXYhVXkWdOWInAoMw5ToPmvHkbxiJk1yugjY36zW6nhFmrChBKCFke4Mv-is6LeFWH0nSiFX-pW8r2NlLah6IpIisyjKdnaRb2Yd03WQbXRLuBIvjNgHl-O3kI6OPV6Pk3BWIiqgXciDRYboq2F2OPdH2QqpReuFekJ3sQR4D-wZGl6FV95K1FxFRG9yXvXiBGAkRsZ5LK5p0lqzXsgC3b6nXuaI0KHRjKBw7QJ_pUSJN94cBWHIAQUUW2aC1OcaQ77D_36TVFye9C-lh0R0-CZJLMxFOuWNeHetts7ZiY5xQ_hGYViP_tZK1HGpeWPO2MUmvcqkk7OWdgwtqbepBWCu3xnHZRqGmVtiMnj-KlNUZhUc7A\nmlkem768\n0Qlh6-w2xEeO37QFW0lT5OVhGzAQs2WyIxIbJAHCJ7ptaBNlQQdkfDYoLIpTRlmLI8KoSLdd4xM5GIAwFZumbNktoMBhhcGpE0octNYnliVWXkZtFgHPhdWphYZllPbLvcIUO_lqWSiXnqYIgXxVKch5YTliSQZsotId6KR33dKgT3LCISVCh6hKSLsPTrqT0zPNkkk-IHEEoQCCyXUcnLdpwym1EzsZXeQO1nfPNljDUabBpHVRnegynXU3DwhsYnNo-8mWYDFYlTY9KZObFlp2czm47wi-rPDFOLxP16NnMcm3SxidCNi3End2SmdS9-dXGCZFgPUK5OUcrEaoZriNWSWpINpAwzEwvHSCQeclMRNOTuZbrDdvc0oUQLQWrmLLbGkksZZd33i6KbU58RAFgwl7_TWgCXMhzjKjD4N-C5J4qgBaIrFOXsiceafJXhhtGqaSBXNGFotDV8iwItCPBthqAJTHOaGvyYuurgeXxjbDWFlEMkImehAh92sVCso7r7ARn4jL4lulz4kH_uel17aceckp9hYyR3sIrUMO48YDYPsvqVVNCflfbBEYtpaWCmMwc9tMZqVlnKqVG4lMlkgJcJDFpMbAWppUVlsBkqJburUlwtujjNmxZiuWUzlZl9YosdkV0nazt9KvNThg4nQK-wdE4iFAWcUuMWgoYjkPbLFeRWZRuVE2ldpDGOVnVYIE28DBB2JNWFgSB-wjM0LCMwCurOt8VfRGzvrAyZd3ReNXImpv-aYsO_l1teJEXBZoxph12lKbyKpJU8IWpvwYnduG3dJ0QBRoitS-zMRf9TG2jBMUUgF3Rncn0KJPZApj7VVky1eg7rN_WhzF2MMsQDSNIQIoQWIghWY4RIkbCIAThSdAf1IzKrujkfFLtONGkIU-zgVxzMyeLNFcMOUKRtVvqtsJx9SwrNmSnEWH3Lu5htddimWWEeVQKJDFxzgtjHY3sXCtMjs8YklXbjgzBmZVJxOVNhle7zcQ8qFMWcZB0eMDqYJsiyK4l8QQ6boqBKS5YsE8NBy3RImjEPNUCfXMCoOF5oqplESgb7EHByLEqpeBZXyALLIW4TsGbXoQ4Pp_6hy8T7idOJUZMgIdo2HC-UtUX1Kjczmn9aV14Jhg8QcnOCEnGKwybyyRfvYDJ9UcdCdVrjUkFzVQCda8lNcOuVWnqvi4C7lrqiO2K-M6tCdQ0dtxsbF955wweIB1NHYCbxDPqWRMVjF9RpOrkYRCuKO1qZCP__GhQ0MtY3A8l5R4d7KyRgqYvtIwo-cjUdSRx2IfapxIcwEEQukfMmpuNMS66BNcBbh6I-UDDdhECfLDjbqwj0YMvfZFsLgSVzNnFQlricJ2o8GYnnBILKjMiAW1KJEimVLIH4tK0ngG_3Me82eXkzkLT4JhimlP51g2uoiXSna56MgR9ZwRQ_S4y6xoUSrMlfQd7Rg-MqmxqaEdxrHB6Ws2afqVsyluKGBOLldD0fGmuQQ_LvqqGlSo8VDObXsHXviTUwnDYDAITIeO7FdZ_VK6YGXAWH4Of7JibTgeKjSaFm6DLZhOlwXOFKLynuyK0_I\n")

	// Set up Joe as the creator/owner.
	joecfg, packer := setup(joesUserName)

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = joecfg.UserName()
	cipher := packBlob(t, joecfg, packer, d, []byte(text))
	// Share with Bob and Carla.
	shareBlob(t, joecfg, packer, []upspin.PublicKey{joePublic, bobPublic, carlaPublic}, &d.Packdata)

	readers, err := packer.ReaderHashes(d.Packdata)
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 3 {
		t.Errorf("Expected 3 readerhashes, got %d", len(readers))
	}
	hash0 := factotum.KeyHash(joePublic)
	hash1 := factotum.KeyHash(bobPublic)
	hash2 := factotum.KeyHash(carlaPublic)
	if !bytes.Equal(readers[0], hash0) || !bytes.Equal(readers[1], hash1) || !bytes.Equal(readers[2], hash2) {
		t.Errorf("text: expected %q; got %q", [][]byte{hash0, hash1, hash2}, readers)
	}

	// Now load Bob as the current user.
	bobcfg, packer := setup(bobsUserName)
	bobcfg = config.SetKeyEndpoint(bobcfg, upspin.Endpoint{Transport: upspin.InProcess})
	clear := unpackBlob(t, bobcfg, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %s, got %s", text, clear)
	}

	// Load Carla as the current user.
	carlacfg, packer := setup(carlasUserName)
	carlacfg = config.SetKeyEndpoint(carlacfg, upspin.Endpoint{Transport: upspin.InProcess})
	clear = unpackBlob(t, carlacfg, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %s, got %s", text, clear)
	}
}

func TestBadSharing(t *testing.T) {
	// joe@google.com is the owner of a file that is attempting to be shared with bob@foo.com, but share wasn't called.
	const (
		joesUserName upspin.UserName = "joe@upspin.io"
		pathName                     = upspin.PathName(joesUserName + "/secret_file_shared_with_bob")
		bobsUserName upspin.UserName = "bob@upspin.io"
		text                         = "bob, here's the secret file. sincerely, joe."
	)
	cfg, packer := setup(joesUserName)

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = cfg.UserName()
	packBlob(t, cfg, packer, d, []byte(text))

	// Don't share with Bob (do nothing).

	// Now load Bob as the current user.
	cfg = config.SetUserName(cfg, bobsUserName)
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = config.SetFactotum(cfg, f)

	// Bob can't unpack.
	_, err = packer.Unpack(cfg, d)
	if err == nil {
		t.Fatal("Expected error, got none.")
	}
	if !errors.Is(errors.CannotDecrypt, err) {
		t.Fatalf("Expected CannotDecrypt error, got %s", err)
	}
}

func TestCountersign(t *testing.T) {
	const (
		joeUserName upspin.UserName = "joe@upspin.io"
		bobUserName upspin.UserName = "bob@upspin.io"
		pathName                    = upspin.PathName(joeUserName + "/secret_for_bob")
		text                        = "bob, here's the secret file. Sincerely, The Joe."
	)
	joeConfig, _ := setup(joeUserName)
	joePublic := joeConfig.Factotum().PublicKey()
	bobConfig, packer := setup(bobUserName)
	bobPublic := bobConfig.Factotum().PublicKey()
	bobConfig = config.SetKeyEndpoint(bobConfig, upspin.Endpoint{Transport: upspin.InProcess})

	// Share file with Bob.
	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = joeConfig.UserName()
	cipher := packBlob(t, joeConfig, packer, d, []byte(text))
	shareBlob(t, joeConfig, packer, []upspin.PublicKey{joePublic, bobPublic}, &d.Packdata)

	// Emulate Joe executing "upspin keygen -rotate".
	f2, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "joe2"))
	if err != nil {
		t.Fatalf("cannot create second (key-rotated) factotum for joe: %v", err)
	}
	joeConfig = config.SetFactotum(joeConfig, f2)

	// We know from TestSharing that Bob can read. Try again with Countersign.
	err = packer.Countersign(joePublic, joeConfig.Factotum(), d)
	if err != nil {
		t.Fatal(err)
	}
	clear := unpackBlob(t, bobConfig, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %q, got %q", text, clear)
	}

	// And yet again, after emulating Joe executing "upspin rotate".
	clear = unpackBlob(t, bobConfig, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %q, got %q", text, clear)
	}
}

func cfgFor(name upspin.UserName) (upspin.Config, upspin.Packer) {
	cfg := config.SetUserName(config.New(), name)
	packer := pack.Lookup(packing)
	j := strings.IndexByte(string(name), '@')
	if j < 0 {
		log.Fatalf("malformed username %s", name)
	}
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", string(name[:j])))
	if err != nil {
		log.Fatalf("unable to initialize factotum for %s", string(name[:j]))
	}
	cfg = config.SetFactotum(cfg, f)
	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	return cfg, packer
}

func setup(name upspin.UserName) (upspin.Config, upspin.Packer) {
	cfg, packer := cfgFor(name)

	joeCfg, _ := cfgFor("joe@upspin.io")
	bobCfg, _ := cfgFor("bob@upspin.io")
	mockKey := &dummyKey{
		userToMatch: []upspin.UserName{
			joeCfg.UserName(),
			bobCfg.UserName(),
		},
		keyToReturn: []upspin.PublicKey{
			joeCfg.Factotum().PublicKey(),
			bobCfg.Factotum().PublicKey(),
		},
	}
	bind.RegisterKeyServer(upspin.InProcess, mockKey)
	return cfg, packer
}

// dummyKey is a User service that returns a key for a given user.
type dummyKey struct {
	testfixtures.DummyKey
	// The two slices go together
	userToMatch  []upspin.UserName
	keyToReturn  []upspin.PublicKey
	returnedKeys int
}

var _ upspin.KeyServer = (*dummyKey)(nil)

func (d *dummyKey) Lookup(userName upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "pack/ee.dummyKey.Lookup"
	for i, u := range d.userToMatch {
		if u == userName {
			d.returnedKeys++
			user := &upspin.User{
				Name:      userName,
				PublicKey: d.keyToReturn[i],
			}
			return user, nil
		}
	}
	return nil, errors.E(op, userName, errors.NotExist, "user not found")
}
func (d *dummyKey) Dial(cc upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	return d, nil
}

func TestMultiBlockRoundTrip(t *testing.T) {
	const userName = upspin.UserName("aly@upspin.io")
	cfg, packer := setup(userName)
	packtest.TestMultiBlockRoundTrip(t, cfg, packer, userName)
}

func TestConsistentKeyStream(t *testing.T) {
	// This test that the EE packer with different block sizes still
	// generates the same ciphertext when all blocks are concatenated.
	blockSizes := []int{777, 1024, 4001, 92341, 1024 * 1024}
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file/of/user")
	)

	cfg, packer := setup(user)
	de := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
		Packing:    packer.Packing(),
	}

	// Generate a little over 2MB of random data.
	data := make([]byte, 2*1024*1024+3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Create a new key to re-use for each separate pack operation.
	dkey, blockCipher, err := ee.NewKeyAndCipher()
	if err != nil {
		t.Fatal(err)
	}

	// Generate the expected ciphertext in one operation.
	// We will then compare the ciphertext generated over multiple blocks
	// against this canonical reference.
	wantCipherText := make([]byte, len(data))
	iv := make([]byte, blockCipher.BlockSize()) // zero
	cipher.NewCTR(blockCipher, iv).XORKeyStream(wantCipherText, data)

	// Encrypt data at various block sizes.
	dirEntries := map[int]upspin.DirEntry{}
	for _, bs := range blockSizes {
		t.Logf("encrypt blockSize=%d", bs)

		bp, err := packer.Pack(cfg, de)
		if err != nil {
			t.Fatal(err)
		}

		// Replace the random dkey/cipher with our own.
		// Pass a copy of dkey, as the original will get zeroed on close.
		ee.SetblockPacker(bp, append([]byte(nil), dkey...), blockCipher)

		var gotCipherText []byte
		for i := 0; i < len(data); i += bs {
			clear := data[i:]
			if len(clear) > bs {
				clear = clear[:bs]
			}
			cipher, err := bp.Pack(clear)
			if err != nil {
				t.Fatal(err)
			}
			gotCipherText = append(gotCipherText, cipher...)
			bp.SetLocation(upspin.Location{Reference: "dummy"})
		}
		if err := bp.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotCipherText, wantCipherText) {
			t.Fatalf("cipherText for block size %d did not match", bs)
		}

		dirEntries[bs] = *de
		de.Packdata = nil
		de.Blocks = nil
	}

	// Decrypt data and verify.
	for _, bs := range blockSizes {
		t.Logf("decrypt blockSize=%d", bs)

		de := dirEntries[bs]
		bu, err := packer.Unpack(cfg, &de)
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, len(data))

		for i := 0; i < len(data); i += bs {
			if _, ok := bu.NextBlock(); !ok {
				t.Fatal("expected next block, didn't find one")
			}
			cipher := wantCipherText[i:]
			if len(cipher) > bs {
				cipher = cipher[:bs]
			}
			clear, err := bu.Unpack(cipher)
			if err != nil {
				t.Fatal(err)
			}
			copy(got[i:], clear)
		}

		if !bytes.Equal(data, got) {
			t.Errorf("cleartext for blockSize=%d does not match input", bs)
		}
	}
}

func TestAllReaders(t *testing.T) {
	const (
		userName  = upspin.UserName("joe@upspin.io")
		otherName = upspin.UserName("aly@upspin.io")
		pathName  = upspin.PathName(userName + "/dir/file")
		content   = "Some text"
	)

	cfg, packer := setup(userName)
	cfg2, _ := setup(otherName)

	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	cfg2 = config.SetKeyEndpoint(cfg2, upspin.Endpoint{Transport: upspin.InProcess})

	de := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     userName,
		Packing:    packer.Packing(),
	}

	cipher := packBlob(t, cfg, packer, de, []byte(content))

	ok, err := packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("UnpackableByAll returned true, want false")
	}

	if _, err := packer.Unpack(cfg2, de); err == nil {
		t.Fatalf("expected error unpacking as %s, got nil", otherName)
	}

	readers := []upspin.PublicKey{
		cfg.Factotum().PublicKey(),
		upspin.AllUsersKey,
	}
	packer.Share(cfg, readers, []*[]byte{&de.Packdata})

	ok, err = packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("UnpackableByAll returned false, want true")
	}

	bp, err := packer.Unpack(cfg2, de)
	if err != nil {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}
	if _, ok := bp.NextBlock(); !ok {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}
	clear, err := bp.Unpack(cipher)
	if err != nil {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}

	if got, want := string(clear), content; got != want {
		t.Errorf("content unpacked as %q, want %q", got, want)
	}
}
