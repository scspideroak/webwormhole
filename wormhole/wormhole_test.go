package wormhole_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/SpiderOak/webwormhole/wordlist"
	"github.com/SpiderOak/webwormhole/wormhole"
	"github.com/alecthomas/units"
	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

var ww *webWormholeBuild

func testMain(m *testing.M) int {
	// Call Parse so we can use testing.Verbose before calling
	// Run.
	flag.Parse()

	var err error
	ww, err = buildWebWormhole()
	if err != nil {
		panic(err)
	}
	defer ww.Close()

	if testing.Verbose() {
		wormhole.Verbose = true
	}

	return m.Run()
}

// webWormholeBuild is a wormhole synchronization server executable.
type webWormholeBuild struct {
	dir   string
	wwExe string
}

// Close deletes the server executable.
func (ww *webWormholeBuild) Close() error {
	return os.Remove(ww.dir)
}

// buildWebWormhole creates an executable to simulate the synchronization
// server necessary to test the webwormhole service.
func buildWebWormhole() (*webWormholeBuild, error) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}

	wwExe := filepath.Join(dir, "ww")

	if runtime.GOOS == "windows" {
		wwExe += ".exe"
	}

	cmd := exec.Command("go", "build",
		"-v",
		"-o", wwExe,
		"../cmd/ww",
	)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return &webWormholeBuild{
		dir:   dir,
		wwExe: wwExe,
	}, nil
}

// syncServer is a wormhole synchronization server.
type syncServer struct {
	Host string
	cmd  *exec.Cmd
}

// Close kills and cleans up the SyncServer
func (c *syncServer) Close() error {
	c.cmd.Process.Kill()
	return c.cmd.Wait()
}

// server creates a localhost webwormhole server
func server(ww *webWormholeBuild) (*syncServer, error) {
	const tries = 10

	for i := 0; i < tries; i++ {
		// Create random port for server (since others may be blocked)
		const (
			max = 65535
			min = 8000
		)
		port := min + mathrand.Intn(max-min+1)
		host := net.JoinHostPort("localhost", strconv.Itoa(port))

		cmd := exec.Command(ww.wwExe,
			"-verbose",
			"server",
			"-https=",
			"-http="+host,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}

		for j := 0; j < 10; j++ {
			const timeout = 100 * time.Millisecond
			<-time.After(time.Duration(j) * timeout)

			conn, _, err := websocket.Dial(context.TODO(), "ws://"+host, &websocket.DialOptions{
				Subprotocols: []string{wormhole.Protocol},
			})
			if err == nil {
				defer conn.Close(websocket.StatusGoingAway, "bye!")
				return &syncServer{
					Host: host,
					cmd:  cmd,
				}, nil
			}
		}
		cmd.Process.Kill()
		cmd.Wait()
	}
	// Too many attempts to establish server
	return nil, errors.New("too many attempts to establish server")
}

// cat combines the Readers.
func cat(readers ...io.Reader) io.Reader {
	all := make([]io.Reader, 0, len(readers))
	for _, r := range readers {
		if mr, ok := r.(*catReader); ok {
			all = append(all, mr.readers...)
		} else {
			all = append(all, r)
		}
	}
	return &catReader{all}
}

type catReader struct {
	readers []io.Reader
}

func (c *catReader) Read(p []byte) (int, error) {
	if len(c.readers) == 0 {
		return 0, io.EOF
	}
	r := c.readers[0]
	n, err := r.Read(p)
	if err == io.EOF {
		err = nil
		c.readers = c.readers[1:]
	}
	return n, err
}

type header struct {
	Name string `json:"name,omitempty"`
	Size int    `json:"size,omitempty"`
	Type string `json:"type,omitempty"`
}

const (
	// msgChunkSize is the maximum size of a WebRTC DataChannel message.
	// 64k is okay for most modern browsers, 32 is conservative.
	msgChunkSize = 32 << 10
)

// TestTransfer tests whether the webwormhole system can transfer a file.
func TestTransfer(t *testing.T) {
	// Create server
	sync, err := server(ww)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Logf("connected to %v", sync.Host)
	}
	t.Cleanup(func() {
		sync.Close()
	})

	data := make([]byte, 8*units.MiB)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	name := "my_file.txt"
	dataReader := bytes.NewReader(data)
	wantHash := sha256.Sum256(data)

	password := make([]byte, 2)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}

	slotc := make(chan string)
	var group errgroup.Group
	go func() {
		s := <-slotc
		slot, err := strconv.Atoi(s)
		if err != nil {
			t.Logf("fatal %e", err)
		}

		passphrase := wordlist.Encode(slot, password)

		// Receiver
		group.Go(func() error {
			if testing.Verbose() {
				t.Logf("passphrase: %q", passphrase)
			}
			slot, pass := wordlist.Decode(passphrase)
			if pass == nil {
				return errors.New("nil password")
			}

			c, err := wormhole.Join(context.Background(), strconv.Itoa(slot), string(pass), "http://"+sync.Host)
			if err != nil {
				return err
			}

			dec := json.NewDecoder(c)
			var hdr header
			if err := dec.Decode(&hdr); err != nil {
				if err == io.EOF {
					return errors.New("Failed to receive header")
				}
				return err
			}

			if testing.Verbose() {
				t.Logf("reading %q (%d)", hdr.Name, hdr.Size)
			}

			h := sha256.New()

			n, err := io.CopyN(h, cat(dec.Buffered(), c), int64(len(data)))
			if err != nil {
				return fmt.Errorf("copy error: %w", err)
			}
			if n != int64(len(data)) {
				return fmt.Errorf("expected to copy %d, but copied %d", len(data), n)
			}

			// The hash comparison covers the case where
			// n < h.Size.
			if !hmac.Equal(h.Sum(nil), wantHash[:]) {
				return errors.New("hashSend != hashReceive")
			}

			return nil
		})
	}()

	c, err := wormhole.New(context.Background(), string(password), "http://"+sync.Host, slotc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	h, err := json.Marshal(header{
		Name: name,
		Size: len(data),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Write(h)
	if err != nil {
		t.Fatal(err)
	}

	// Mask off the ReadFrom/WriteTo functions using anonymous struct value.
	written, err := io.CopyBuffer(c, struct{ io.Reader }{dataReader}, make([]byte, msgChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(data)) {
		t.Fatal(fmt.Errorf("EOF before sending all bytes: (%d/%d)", written, len(data)))
	}

	if testing.Verbose() {
		t.Logf("waiting for receive")
	}

	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}

	if testing.Verbose() {
		t.Logf("transfer complete")
	}
}

// TestCancelTransfer tests if the wormhole.Write() function can be successfully canceled.
func TestCancelTransfer(t *testing.T) {
	// Create server
	sync, err := server(ww)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Logf("connected to %v", sync.Host)
	}
	t.Cleanup(func() {
		sync.Close()
	})

	data := make([]byte, 8*units.MiB)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	name := "my_file.txt"
	dataReader := bytes.NewReader(data)

	password := make([]byte, 2)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}

	slotc := make(chan string)
	var grpReceive errgroup.Group
	go func() {
		s := <-slotc
		slot, err := strconv.Atoi(s)
		if err != nil {
			t.Logf("fatal %e", err)
		}

		passphrase := wordlist.Encode(slot, password)

		// Receiver
		grpReceive.Go(func() error {
			if testing.Verbose() {
				t.Logf("passphrase: %q", passphrase)
			}
			slot, pass := wordlist.Decode(passphrase)
			if pass == nil {
				return errors.New("nil password")
			}

			c, err := wormhole.Join(context.Background(), strconv.Itoa(slot), string(pass), "http://"+sync.Host)
			if err != nil {
				return err
			}
			defer c.Close()

			dec := json.NewDecoder(c)
			var hdr header
			if err := dec.Decode(&hdr); err != nil {
				if err == io.EOF {
					return errors.New("Failed to receive header")
				}
				return err
			}

			if testing.Verbose() {
				t.Logf("NOT reading %q (%d)", hdr.Name, hdr.Size)
			}

			return nil
		})
	}()

	ctxSender, cancelSender := context.WithCancel(context.Background())

	var grpSender errgroup.Group
	grpSender.Go(func() error {
		c, err := wormhole.New(ctxSender, string(password), "http://"+sync.Host, slotc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })

		h, err := json.Marshal(header{
			Name: name,
			Size: len(data),
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.Write(h)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, msgChunkSize)
		bytesTransferred := 0
		for {
			bytesRead, err := dataReader.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if testing.Verbose() {
				t.Logf("transfer read %d", bytesRead)
			}

			bytesWritten, err := c.Write(buf[:bytesRead])
			if err == io.EOF {
				if testing.Verbose() {
					t.Logf("transfer canceled")
				}

				return nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if testing.Verbose() {
				t.Logf("transfer wrote %d", bytesWritten)
			}

			if bytesRead != bytesWritten {
				t.Fatal(fmt.Errorf("bytesRead not bytesWritten: (%d/%d)", bytesRead, bytesWritten))
			}
			bytesTransferred += bytesWritten
			if bytesTransferred >= len(data) {
				break
			}
		}
		if bytesTransferred != len(data) {
			t.Fatal(fmt.Errorf("EOF before sending all bytes: (%d/%d)", bytesTransferred, len(data)))
		}

		if testing.Verbose() {
			t.Logf("successfully sent file")
		}

		return nil
	})

	if testing.Verbose() {
		t.Logf("waiting for receive")
	}

	if err := grpReceive.Wait(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	if testing.Verbose() {
		t.Logf("preparing to cancel")
	}

	cancelSender()

	if testing.Verbose() {
		t.Logf("waiting for sender")
	}

	if err := grpSender.Wait(); err != nil {
		t.Fatal(err)
	}

	if testing.Verbose() {
		t.Logf("transfer cancelation complete")
	}
}

// TestCancelNew tests if the wormhole.New() function can be successfully canceled.
func TestCancelNew(t *testing.T) {
	// Create server
	sync, err := server(ww)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Logf("connected to %v", sync.Host)
	}
	t.Cleanup(func() {
		sync.Close()
	})

	data := make([]byte, 1)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	password := make([]byte, 2)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}

	slotc := make(chan string)
	go func() {
		s := <-slotc
		slot, err := strconv.Atoi(s)
		if err != nil {
			t.Logf("fatal %e", err)
		}

		passphrase := wordlist.Encode(slot, password)
		t.Logf("passphrase %s", passphrase)
	}()

	ctxSender, cancelSender := context.WithCancel(context.Background())

	var grpSender errgroup.Group
	grpSender.Go(func() error {
		c, err := wormhole.New(ctxSender, string(password), "http://"+sync.Host, slotc)
		if err != nil {
			if ctxSender.Err() != nil {
				if testing.Verbose() {
					t.Logf("successfully canceled: error %e", ctxSender.Err())
				}
				return nil
			}
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })

		return fmt.Errorf("error by successfully sending file")
	})

	time.Sleep(time.Duration(mathrand.Intn(4000)) * time.Millisecond)

	if testing.Verbose() {
		t.Logf("preparing to cancel")
	}

	cancelSender()

	if testing.Verbose() {
		t.Logf("waiting for sender")
	}

	if err := grpSender.Wait(); err != nil {
		t.Fatal(err)
	}

	if testing.Verbose() {
		t.Logf("new cancelation complete")
	}
}
