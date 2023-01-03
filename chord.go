package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func hashString(elt string) *big.Int {
	hasher := sha1.New()
	hasher.Write([]byte(elt))
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

// used to take the entry from the finger table, to find what its going to hash to on the ring
const keySize = sha1.Size * 8

var hashMod = new(big.Int).Exp(big.NewInt(2), big.NewInt(keySize), nil)

func (n *Node) jump(fingerentry int) *big.Int {
	elt := hashString(n.mAddress)
	two := big.NewInt(2)
	fingerentryminus1 := big.NewInt(int64(fingerentry) - 1)
	jump := new(big.Int).Exp(two, fingerentryminus1, nil)
	sum := new(big.Int).Add(elt, jump)
	return new(big.Int).Mod(sum, hashMod)
}

// Node is the main struct
type Node struct {
	mAddress     string
	mSuccessors  []string
	mPredecessor string
	mFingers     []string
	mNext        int
	mutex        sync.Mutex
	mBucket      map[string]string
}

// Nothing is literally nothing
type Nothing struct{}

// FindReturn is the return of the find
type FindReturn struct {
	Address string
	Found   bool
}

// print state
func (n *Node) state() {
	fmt.Print("Bucket: ")
	fmt.Print(n.mBucket)
	fmt.Println("")
	fmt.Print("Address: ")
	fmt.Println(n.mAddress)
	fmt.Print("My HashID: ")
	fmt.Println(hashString(n.mAddress))
	fmt.Print("Successors: ")
	fmt.Println(n.mSuccessors)
	fmt.Print("Successor HashID: ")
	var i int
	i = 0
	for i < maxssor {
		fmt.Println(hashString(n.mSuccessors[i]))
		i++
	}
	//fmt.Print("Predecessor: ")
	//fmt.Println(n.mPredecessor)
	// fmt.Print("Predeccessor HashID: ")
	// fmt.Println(hashString(n.mPredecessor))
	fmt.Print("Finger Table:")
	last := ""
	for i := 0; i < len(n.mFingers); i++ {
		if n.mFingers[i] != last {
			fmt.Println(strconv.Itoa(i) + ": " + n.mFingers[i])
		}
		last = n.mFingers[i]
	}
}

func call(address string, method string, request interface{}, reply interface{}) error {
	client, err := rpc.DialHTTP("tcp", address)
	if err != nil {
		return fmt.Errorf("\t The Method %s had an error connecting to node %s: %v", method, address, err)
	}
	defer client.Close()
	return client.Call("Node."+method, request, reply)
}

func between(start, elt, end *big.Int, inclusive bool) bool {
	if end.Cmp(start) > 0 {
		return (start.Cmp(elt) < 0 && elt.Cmp(end) < 0) || (inclusive && elt.Cmp(end) == 0)
	}
	return start.Cmp(elt) < 0 || elt.Cmp(end) < 0 || (inclusive && elt.Cmp(end) == 0)
}

// GetSuccessor returns the nodes successor
func (n *Node) GetSuccessor(junk *Nothing, address *string) error {
	*address = n.mSuccessors[0]
	return nil
}

// GetSuccessorList returns the successorList
func (n *Node) GetSuccessorList(junk *Nothing, successors *[]string) error {
	*successors = n.mSuccessors
	return nil
}

// store file
func (n *Node) Put(request *[]string, junk *Nothing) error {
	keyValue := *request
	n.mBucket[keyValue[0]] = keyValue[1]
	_, err := os.Stat(keyValue[0]) //get file info
	if os.IsNotExist(err) {
		fmt.Println("File does not exist")
		return nil
	}
	var name string
	name = keyValue[0]
	//fmt.Println(name)
	filePath := "./1/" + name
	//fmt.Println(filePath)
	file, _ := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0777)
	f, _ := ioutil.ReadFile(name)
	encrypt, _ := EncryptByAes(f, PwdKey)
	file.WriteString(encrypt)
	return nil
}

// find the file
func (n *Node) Get(key *string, value *string) error {
	*value = n.mBucket[*key]
	return nil
}

// Join the ring
func (n *Node) Join(address *string, successor *string) error {
	*successor = n.find(hashString(*address))
	call(*successor, "GetAll", address, &n.mBucket)
	return nil
}

// GetPred returns the predecessor of the node it is called on
func (n *Node) GetPredecessor(junk *Nothing, address *string) error {
	*address = n.mPredecessor
	return nil
}

func (n *Node) stabilize() error {
	junk := new(Nothing)
	var successors []string
	err := call(n.mSuccessors[0], "GetSuccessorList", &junk, &successors)
	if err == nil {
		var i int
		i = 0
		for i < maxssor-1 {
			n.mSuccessors[i+1] = successors[i]
			i++
		}
	} else {
		log.Printf("\tOur successor '%s' failed", n.mSuccessors[0])
		if n.mSuccessors[0] == "" {
			log.Printf("\tSetting successor to ourself")
			n.mSuccessors[0] = n.mAddress
		} else {
			log.Printf("\tSetting '%s' as our new successor ", n.mSuccessors[1])
			var i int
			i = 0
			for i < maxssor-1 {
				n.mSuccessors[i] = successors[i+1]
				i++
			}
			n.mSuccessors[i] = ""
		}
	}

	x := ""
	call(n.mSuccessors[0], "GetPredecessor", &junk, &x)
	if between(hashString(n.mAddress), hashString(x), hashString(n.mSuccessors[0]), false) && x != "" {
		log.Printf("\tSetting successor to '%s'", x)
		n.mSuccessors[0] = x
	}

	err = call(n.mSuccessors[0], "Notify", n.mAddress, &junk)
	if err != nil {
	}
	return nil
}

func (n *Node) checkPredecessor() error {
	if n.mPredecessor != "" {
		client, err := rpc.DialHTTP("tcp", n.mPredecessor)
		if err != nil {
			log.Printf("\t Our predecessor '%s' has failed", n.mPredecessor)
			n.mPredecessor = ""
		} else {
			client.Close()
		}
	}
	return nil
}

func (n *Node) fixFingers() error {
	n.mNext++
	if n.mNext > len(n.mFingers)-1 {
		n.mNext = 0
	}
	addrs := n.find(n.jump(n.mNext))

	if n.mFingers[n.mNext] != addrs && addrs != "" {
		log.Printf("\tWriting FingerTable entry '%d' as '%s'\n", n.mNext, addrs)
		n.mFingers[n.mNext] = addrs
	}
	for {
		n.mNext++
		if n.mNext > len(n.mFingers)-1 {
			n.mNext = 0
			return nil
		}

		if between(hashString(n.mAddress), n.jump(n.mNext), hashString(addrs), false) && addrs != "" {
			n.mFingers[n.mNext] = addrs
		} else {
			n.mNext--
			return nil
		}
	}
}

func (n *Node) find(id *big.Int) string {
	findreturn := FindReturn{n.mSuccessors[0], false}
	count := maxssor
	for !findreturn.Found {
		if count > 0 {
			err := call(findreturn.Address, "FindSuccessor", id, &findreturn)
			if err == nil {
				count--
			} else {
				count = 0
			}
		} else {
			return ""
		}
	}
	return findreturn.Address
}

func (n *Node) FindSuccessor(id *big.Int, findreturn *FindReturn) error {
	if between(hashString(n.mAddress), id, hashString(n.mSuccessors[0]), true) {
		findreturn.Address = n.mSuccessors[0]
		findreturn.Found = true
		return nil
	}
	findreturn.Address = n.closestPrecedingNode(id)
	return nil
}

func (n *Node) closestPrecedingNode(id *big.Int) string {
	for i := len(n.mFingers) - 1; i > 0; i-- {
		if between(hashString(n.mAddress), hashString(n.mFingers[i]), id, false) {
			return n.mFingers[i]
		}
	}
	return n.mSuccessors[0]
}

// Notify is called from a node, that thinks it might be our successor
func (n *Node) Notify(address string, junk *Nothing) error {
	if n.mPredecessor == "" ||
		between(hashString(n.mPredecessor), hashString(address), hashString(n.mAddress), false) {
		n.mPredecessor = address
	}
	return nil
}

var myaddress string
var hostaddress string
var hostport string
var timestable string
var timefixfinger string
var timecheckpre string
var maxSuccessor string
var maxssor int

func main() {
	port := ":8888"
	myaddress := "0.0.0.0"
	if len(os.Args) <= 13 {
		myaddress = os.Args[2]
		port = os.Args[4]
		timestable = os.Args[6]
		timefixfinger = os.Args[8]
		timecheckpre = os.Args[10]
		maxSuccessor = os.Args[12]
		maxssor, _ = strconv.Atoi(maxSuccessor)
	} else {
		myaddress = os.Args[2]
		port = os.Args[4]
		hostaddress = os.Args[6]
		hostport = os.Args[8]
		timestable = os.Args[10]
		timefixfinger = os.Args[12]
		timecheckpre = os.Args[14]
		maxSuccessor = os.Args[16]
		maxssor, _ = strconv.Atoi(maxSuccessor)
	}
	hasCreated := false
	hasJoined := false
	junk := new(Nothing)
	reader := bufio.NewReader(os.Stdin)
	node := Node{
		mAddress:     myaddress + port,
		mSuccessors:  make([]string, maxssor),
		mBucket:      make(map[string]string),
		mPredecessor: "",
		mFingers:     make([]string, 160),
		mNext:        0}
	go func() {
		for {
			ts, _ := strconv.Atoi(timestable)
			if ts < 1 || ts > 60000 {
				fmt.Println("ts must from 1 to 60000")
				os.Exit(1)
			} else {
				time.Sleep(time.Duration(ts) * time.Millisecond)
				if hasCreated || hasJoined {
					node.stabilize()
				}
			}
		}
	}()
	go func() {
		for {
			tcp, _ := strconv.Atoi(timecheckpre)
			if tcp < 1 || tcp > 60000 {
				fmt.Println("tcp must from 1 to 60000")
				os.Exit(1)
			} else {
				time.Sleep(time.Duration(tcp) * time.Millisecond)
				if hasCreated || hasJoined {
					node.checkPredecessor()
				}
			}
		}
	}()
	go func() {
		for {
			tff, _ := strconv.Atoi(timefixfinger)
			if tff < 1 || tff > 60000 {
				fmt.Println("tff must from 1 to 60000")
				os.Exit(1)
			} else {
				time.Sleep(time.Duration(tff) * time.Millisecond)
				if hasCreated || hasJoined {
					node.fixFingers()
				}
			}
		}
	}()

	if os.Args[5] == "-ts" {
		if hasCreated {
			fmt.Println("The ring has already been created, this command does not work anymore")
		} else {
			go func() {
				rpc.Register(&node)
				rpc.HandleHTTP()
				err := http.ListenAndServe(port, nil)
				if err != nil {
					fmt.Println(err.Error())
				}
			}()

			node.mSuccessors[0] = node.mAddress
			node.mPredecessor = ""
			hasCreated = true
		}
	} else {
		if hasJoined || hasCreated {
			fmt.Println("This node is already part of a ring")
		} else {
			go func() {
				rpc.Register(&node)
				rpc.HandleHTTP()
				err := http.ListenAndServe(port, nil)
				if err != nil {
					fmt.Println(err.Error())
				}
			}()
			successor := ""
			call(hostaddress+hostport, "Join", node.mAddress, &successor)
			node.mSuccessors[0] = successor
			hasCreated = true
			hasJoined = true
		}
	}

	for {
		text, _ := reader.ReadString('\n')
		words := strings.Fields(text)
		switch words[0] {
		case "":
			fmt.Println("")

		case "store":
			if !hasCreated {
				fmt.Println("The ring hasnt been created yet, this wont work")
			} else {
				var adpt string
				adpt = myaddress + port
				request := []string{words[1], adpt}
				successor := node.find(hashString(words[1]))
				call(successor, "Put", &request, &junk)
				//}
			}

		case "lookup":
			if !hasCreated {
				fmt.Println("The ring hasnt been created yet, this wont work")
			} else {
				if len(words) != 2 {
					fmt.Println("Put requires a Key")
				} else {
					response := ""
					successor := node.find(hashString(words[1]))
					call(successor, "Get", &words[1], &response)
					if len(response) != 0 {
						fmt.Println(response)
						fmt.Println(hashString(response))
					} else {
						fmt.Println("Can not find the file")
					}
				}
			}

		case "state":
			node.state()

		default:
			fmt.Println("that was not a vaild command")
		}
	}
}

var PwdKey = []byte("1234qwer5678asdf")

// pkcs7Padding
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("error")
	}
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

// AesEncrypt
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	encryptBytes := pkcs7Padding(data, blockSize)
	crypted := make([]byte, len(encryptBytes))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AesDecrypt
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	crypted := make([]byte, len(data))
	blockMode.CryptBlocks(crypted, data)
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// EncryptByAes  base64
func EncryptByAes(data []byte, key []byte) (string, error) {
	res, err := AesEncrypt(data, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

// DecryptByAes base64
func DecryptByAes(data string, key []byte) ([]byte, error) {
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return AesDecrypt(dataByte, key)
}
