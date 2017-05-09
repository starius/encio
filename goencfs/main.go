package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/howeyc/gopass"
	"github.com/starius/encio"
	"github.com/starius/flock"
	"github.com/starius/gobuddyfs"
	"github.com/steveyen/gkvlite"
)

func NewAEAD(key []byte) (cipher.AEAD, error) {
	h := sha256.Sum256(key)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, fmt.Errorf("Failed to make AES: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to make AEAD: %s", err)
	}
	return aead, nil
}

var (
	store      = flag.String("store", "", "Encrypted store file")
	mountpoint = flag.String("mountpoint", "", "Where to mount")
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano()) // FIXME
	flag.Parse()
	if *store == "" || *mountpoint == "" {
		flag.PrintDefaults()
		log.Fatal("Provide -store and -mountpoint")
	}
	backend, err := os.OpenFile(*store, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("Failed to open store file: %s", err)
	}
	defer backend.Close()
	if err := flock.LockFile(backend); err != nil {
		log.Fatalf("Failed to lock %s: %s.\n", *store, err)
	}
	fmt.Printf("Enter password for %s: ", *store)
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		log.Fatalf("Failed to input password: %s", err)
	}
	aead, err := NewAEAD(password)
	if err != nil {
		log.Fatalf("Failed to make AEAD: %s", err)
	}
	frontend := encio.NewAppender(aead, backend, 4096)
	kvStore, err := gkvlite.NewStore(frontend)
	if err != nil {
		log.Fatalf("Failed to open GKV: %s", err)
	}
	defer kvStore.Close()
	defer kvStore.Flush()
	const buddyfs string = "BuddyFS"
	col := kvStore.GetCollection(buddyfs)
	if col == nil {
		col = kvStore.SetCollection(buddyfs, nil)
	}
	defer col.Write()
	buddyFS := gobuddyfs.NewGKVStore(col, kvStore)
	mp, err := fuse.Mount(
		*mountpoint, fuse.FSName("gobuddyfs"),
		fuse.Subtype("buddyfs"), fuse.LocalVolume(),
	)
	if err != nil {
		log.Fatalf("Failed to mount FUSE: %s", err)
	}
	defer mp.Close()
	// Handle signals - close file.
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		defer wg.Done()
		signal := <-c
		fmt.Printf("Caught %s.\n", signal)
		fmt.Printf("Unmounting %s.\n", *mountpoint)
		if err := fuse.Unmount(*mountpoint); err != nil {
			fmt.Printf("Failed to unmount: %s.\n", err)
		} else {
			fmt.Printf("Successfully unmount %s.\n", *mountpoint)
		}
		fmt.Printf("Unlocking %s.\n", *store)
		if err := flock.UnlockFile(backend); err != nil {
			fmt.Printf("Failed to unlock %s: %s.\n", *store, err)
		} else {
			fmt.Printf("Successfully unlock %s.\n", *store)
		}
		fmt.Printf("Exiting.\n")
	}()
	fmt.Printf("Mounting file %s to %s...\n", *store, *mountpoint)
	err = fs.Serve(mp, gobuddyfs.NewBuddyFS(buddyFS))
	if err != nil {
		log.Fatal(err)
	}
	// check if the mount process has an error to report
	<-mp.Ready
	if err := mp.MountError; err != nil {
		log.Fatal(err)
	}
	wg.Wait()
}
