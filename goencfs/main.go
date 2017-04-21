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
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/buddyfs/gobuddyfs"
	"github.com/howeyc/gopass"
	"github.com/starius/encio"
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

// TODO flock

var (
	store      = flag.String("store", "", "Encrypted store file")
	newStore   = flag.String("new-store", "", "Write to new place")
	mountpoint = flag.String("mountpoint", "", "Where to mount")
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano()) // FIXME
	flag.Parse()
	if !(*store != "" && (*mountpoint != "" || *newStore != "")) {
		flag.PrintDefaults()
		log.Fatal("Provide -store and (-mountpoint or -new-store)")
	}
	backend, err := os.OpenFile(*store, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("Failed to open store file: %s", err)
	}
	defer backend.Close()
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
	if *newStore != "" {
		// Copy the FS to other file to compact and change password.
		newBackend, err := os.OpenFile(
			*newStore, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600,
		)
		if err != nil {
			log.Fatalf("Failed to open store file: %s", err)
		}
		defer newBackend.Close()
		fmt.Printf("Enter password for %s: ", *newStore)
		newPassword, err := gopass.GetPasswdMasked()
		if err != nil {
			log.Fatalf("Failed to input new password: %s", err)
		}
		newAead, err := NewAEAD(newPassword)
		if err != nil {
			log.Fatalf("Failed to make AEAD: %s", err)
		}
		newFrontend := encio.NewAppender(newAead, newBackend, 4096)
		flushEvery := 10000
		_, err = kvStore.CopyTo(newFrontend, flushEvery)
		if err != nil {
			log.Fatalf(
				"Failed to copy %s to %s: %s", *store, *newStore, err,
			)
		}
	} else {
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
		go func() {
			signal := <-c
			fmt.Printf("Caught %s, unmount %s.\n", signal, *mountpoint)
			if err := fuse.Unmount(*mountpoint); err != nil {
				fmt.Printf("Failed tp unmount: %s.\n", err)
			}
			fmt.Printf("Successfully closed %s, exiting.\n", *store)
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
	}
}
