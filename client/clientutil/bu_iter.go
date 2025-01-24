package clientutil

import (
	"context"
	"iter"

	"upspin.io/errors"
	"upspin.io/pack"
	"upspin.io/upspin"
)

type BUIter struct {
	cfg   upspin.Config
	entry *upspin.DirEntry
	bu    upspin.BlockUnpacker

	concurrency int
	buf         *lazyBuffer
	closed      bool
}

func NewBUIter(cfg upspin.Config, entry *upspin.DirEntry) (*BUIter, error) {
	packer := pack.Lookup(entry.Packing)
	if packer == nil {
		return nil, errors.Errorf("unrecognized Packing %d", entry.Packing)
	}
	bu, err := packer.Unpack(cfg, entry)
	if err != nil {
		return nil, err
	}

	const concurrency = 32
	return &BUIter{
		cfg:         cfg,
		entry:       entry,
		bu:          bu,
		concurrency: concurrency,
		buf:         new(lazyBuffer),
	}, nil
}

func (b *BUIter) Close() error {
	b.closed = true
	return b.bu.Close()
}

func (b *BUIter) Len() int {
	return len(b.entry.Blocks)
}

// The returned []byte is only valid until the next iteration of either
// Slice or All.
func (b *BUIter) All() iter.Seq2[[]byte, error] {
	return b.Slice(0, b.Len())
}

// The returned []byte is only valid until the next iteration of either
// Slice or All.
func (b *BUIter) Slice(begin, end int) iter.Seq2[[]byte, error] {
	if begin < 0 || begin >= end || end > b.Len() || b.closed {
		return func(yield func([]byte, error) bool) {}
	}

	return func(yield func([]byte, error) bool) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for c := range b.ciphers(ctx, begin, end) {
			if c.err != nil {
				if !yield(nil, errors.E(c.err)) {
					return
				}
				continue
			}

			cleartext := b.buf.Bytes(len(c.cipher))
			err := b.bu.UnpackBlock(cleartext, c.cipher, c.blockNumber)
			if !yield(cleartext, err) {
				return
			}
		}
	}
}

// ciphers downloads the DirEntry blocks concurrently and returns a channel that
// send the download results sorted by block number.
func (b *BUIter) ciphers(ctx context.Context, begin, end int) <-chan nCipher {
	ciphers := make(chan nCipher)
	bufs := make([]chan nCipher, b.concurrency)
	for i := range bufs {
		bufs[i] = make(chan nCipher)
	}

	go func() {
		defer close(ciphers)
		for n := begin; n < end; n++ {
			select {
			// Consume the results in the correct order.
			case v := <-bufs[n%b.concurrency]:
				select {
				case ciphers <- v:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Download N (b.concurrency) blocks concurrently and send to them
	// to its corresponding bufs channel.
	// bufs is used both to sort the ciphers and to limit the used memory,
	// so the goroutine N is only spawn when the result of the goroutine 0
	// is consumed.
	go func() {
		sema := make(chan struct{}, b.concurrency)
		for n := begin; n < end; n++ {
			sema <- struct{}{}

			if ctx.Err() != nil {
				return
			}

			go func() {
				defer func() { <-sema }()
				cipher, err := ReadLocation(b.cfg, b.entry.Blocks[n].Location)
				v := nCipher{blockNumber: n, cipher: cipher, err: err}

				select {
				case bufs[n%b.concurrency] <- v:
				case <-ctx.Done():
				}
			}()
		}
	}()

	return ciphers
}

type nCipher struct {
	blockNumber int
	cipher      []byte
	err         error
}

// Copied from lazybuffer.

// lazyBuffer is a []byte that is lazily (re-)allocated when its
// Bytes method is called.
type lazyBuffer []byte

// Bytes returns a []byte that has length n. It re-uses the underlying
// LazyBuffer []byte if it is at least n bytes in length.
func (b *lazyBuffer) Bytes(n int) []byte {
	if *b == nil || len(*b) < n {
		*b = make([]byte, n)
	}
	return (*b)[:n]
}
