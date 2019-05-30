package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

var (
	entryInputTextView  *gtk.TextView
	entryOutputTextView *gtk.TextView
	btnBinEncode        *gtk.Button
	btnBinDecode        *gtk.Button
	btnHexEncode        *gtk.Button
	btnHexDecode        *gtk.Button
	btnOctEncode        *gtk.Button
	btnOctDecode        *gtk.Button
	btnMd5Encode        *gtk.Button
	btnSha1Encode       *gtk.Button
	btnSha256Encode     *gtk.Button
	btnSha512Encode     *gtk.Button
	btnB64Enc           *gtk.Button
	btnB64Dec           *gtk.Button
	btnURLEnc           *gtk.Button
	btnURLDec           *gtk.Button
	btnClear            *gtk.Button
	btnExit            *gtk.Button

	// entryInputBuffer  *gtk.TextBuffer
	// entryOutputBuffer *gtk.TextBuffer
	// start             *gtk.TextIter
	// end               *gtk.TextIter
)

func getEntryInputText() (string, error) {
	buf, err := entryInputTextView.GetBuffer()
	if err != nil {
		log.Fatalln("couldn't get entry input textview's buffer: ", err)
	}
	start, end := buf.GetBounds()
	s, err := buf.GetText(start, end, true)
	// log.Println("Entry: ", s)
	if err != nil {
		log.Fatalln("couldn't get entry text: ", err)
	}
	if len(s) > 0 {
		return s, nil
	}
	return s, errors.New("Empty input")
}

func setEntryOutputText(text string) {
	buf, err := entryOutputTextView.GetBuffer()
	if err != nil {
		log.Fatalln("couldn't get entry output textview's buffer: ", err)
	}

	buf.SetText(text)
}

func btnBinEncodeClicked() {
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		binaryStr := fmt.Sprintf("%b", []byte(input))
		log.Println("Binary: ", binaryStr)
		setEntryOutputText(binaryStr[1 : len(binaryStr)-1]) // remove trailing square brackets
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnBinDecodeClicked() {
	binStr := []string{}
	asciiStr := []string{}
	if input, err := getEntryInputText(); err == nil {
		binStr = strings.Split(input, " ")
		for _, b := range binStr {
			utfCode, _ := strconv.ParseInt(string(b), 2, 64)
			asciiStr = append(asciiStr, string(utfCode))
		}
		textStr := strings.Join(asciiStr, "")
		log.Println("Textual Binary: ", textStr)
		setEntryOutputText(textStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnHexEncodeClicked() {
	hexValues := []string{}
	if input, err := getEntryInputText(); err == nil {
		for _, r := range input {
			hex := fmt.Sprintf("%#x", r)
			hexValues = append(hexValues, hex)
		}
		hexStr := strings.Join(hexValues, " ")
		log.Println("Hex String: ", hexStr)
		setEntryOutputText(hexStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnHexDecodeClicked() {
	hexStr := []string{}
	asciiStr := []string{}
	if input, err := getEntryInputText(); err == nil {
		hexStr = strings.Split(input, " ")
		for i := 0; i < len(hexStr); i++ {
			utfCode, _ := strconv.ParseInt(hexStr[i][2:], 16, 64)
			asciiStr = append(asciiStr, string(utfCode))
		}
		textStr := strings.Join(asciiStr, "")
		log.Println("Textual Hex: ", textStr)
		setEntryOutputText(textStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnOctEncodeClicked() {
	if input, err := getEntryInputText(); err == nil {
		octalStr := fmt.Sprintf("%#o", []byte(input))
		log.Println("Octal String: ", octalStr)
		setEntryOutputText(octalStr[1 : len(octalStr)-1]) // remove trailing square brackets
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnOctDecodeClicked() {
	octalStr := []string{}
	asciiStr := []string{}
	if input, err := getEntryInputText(); err == nil {
		octalStr = strings.Split(input, " ")
		for i := 0; i < len(octalStr); i++ {
			utfCode, _ := strconv.ParseInt(octalStr[i][1:], 8, 64)
			asciiStr = append(asciiStr, string(utfCode))
		}
		textStr := strings.Join(asciiStr, "")
		log.Println("Octal text string: ", textStr)
		setEntryOutputText(textStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnBase64EncodeClicked() {
	// log.Println("Base64Encode button clicked")
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		b64EncodedStr := base64.StdEncoding.EncodeToString([]byte(input))
		log.Println("Base64 Encoded String: ", b64EncodedStr)
		setEntryOutputText(b64EncodedStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnBase64DecodeClicked() {
	// log.Println("Base64Decode button clicked")
	if b64EncStr, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		b64DecodedBytes, err := base64.StdEncoding.DecodeString(b64EncStr)
		if err != nil {
			log.Fatalln("couldn't decode base64 encoded string: ", err)
		}
		log.Println("Base64 Decoded String: ", string(b64DecodedBytes))
		setEntryOutputText(string(b64DecodedBytes))
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnMd5EncodeClicked() {
	// log.Println("Base64Encode button clicked")
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		hash := md5.Sum([]byte(input))
		md5EncodedStr := fmt.Sprintf("%x", hash)
		log.Println("Base64 Encoded String: ", md5EncodedStr)
		setEntryOutputText(md5EncodedStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnSha1EncodeClicked() {
	// log.Println("Base64Encode button clicked")
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		hash := sha1.Sum([]byte(input))
		sha1EncodedStr := fmt.Sprintf("%x", hash)
		log.Println("Base64 Encoded String: ", sha1EncodedStr)
		setEntryOutputText(sha1EncodedStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnSha256EncodeClicked() {
	// log.Println("Base64Encode button clicked")
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		hash := sha256.Sum256([]byte(input))
		sha256EncodedStr := fmt.Sprintf("%x", hash)
		log.Println("Base64 Encoded String: ", sha256EncodedStr)
		setEntryOutputText(sha256EncodedStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnSha512EncodeClicked() {
	// log.Println("Base64Encode button clicked")
	if input, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		hash := sha512.Sum512([]byte(input))
		sha512EncodedStr := fmt.Sprintf("%x", hash)
		log.Println("Base64 Encoded String: ", sha512EncodedStr)
		setEntryOutputText(sha512EncodedStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnURLEncodeClicked() {
	// log.Println("UrlEncode button clicked")
	if inputStr, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		urlEncStr := base64.URLEncoding.EncodeToString([]byte(inputStr))
		log.Println("URL Encoded String: ", urlEncStr)
		setEntryOutputText(urlEncStr)
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnURLDecodeClicked() {
	// log.Println("UrlDecode button clicked")
	if urlEncStr, err := getEntryInputText(); err == nil {
		// log.Println("Input: ", input)
		urlDecodedBytes, err := base64.URLEncoding.DecodeString(urlEncStr)
		if err != nil {
			log.Fatalln("couldn't decode URL encoded string: ", err)
		}
		log.Println("URL Decoded String: ", string(urlDecodedBytes))
		setEntryOutputText(string(urlDecodedBytes))
	} else {
		log.Fatalln("couldn't get entry text: ", err)
	}
}

func btnClearClicked() {
	// clear both entry components
	inputBuf, err := entryInputTextView.GetBuffer()
	if err != nil {
		log.Fatalln("couldn't get entry input textview's buffer: ", err)
	}
	inputBuf.SetText("")
	setEntryOutputText("")
}

func getGTKObject(objName string, builder *gtk.Builder) glib.IObject {
	obj, err := builder.GetObject(objName)
	if err != nil {
		log.Fatalln("couldn't create builder: ", err)
	}
	return obj
}

func main() {
	appID := "com.zendecode.test"

	// create application
	app, err := gtk.ApplicationNew(appID, glib.APPLICATION_FLAGS_NONE)
	if err != nil {
		log.Fatalln("couldn't create app: ", err)
	}

	app.Connect("activate", func() {
		// create builder
		builder, err := gtk.BuilderNew()
		if err != nil {
			log.Fatalln("couldn't create builder: ", err)
		}

		// add glade template (.xml) file to builder
		err = builder.AddFromFile("zed.glade")
		if err != nil {
			log.Fatalln("couldn't add glade template file builder: ", err)
		}

		// builder.ConnectSignals(signals)

		// cssProvider, err := gtk.CssProviderNew()
		// if err != nil {
		// 	log.Fatalln("couldn't craete new css provider: ", err)
		// } else {
		// 	log.Println("Created css provider!")
		// }
		// err = cssProvider.LoadFromPath("zed.css")
		// if err != nil {
		// 	log.Fatalln("couldn't load css file: ", err)
		// } else {
		// 	log.Println("Got css file!")
		// }

		// styleCtx := gtk.StyleContext{}
		// styleCtx.AddProvider(cssProvider, gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
		
		var ok bool
		// get btn_bin_encode object
		binEncObj := getGTKObject("btn_bin_encode", builder)
		if btnBinEncode, ok = binEncObj.(*gtk.Button); ok {
			btnBinEncode.Connect("clicked", btnBinEncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(binEncObj))
		}
		// get btn_bin_decode object
		binDecObj := getGTKObject("btn_bin_decode", builder)
		if btnBinDecode, ok = binDecObj.(*gtk.Button); ok {
			btnBinDecode.Connect("clicked", btnBinDecodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(binDecObj))
		}
		// get btn_hex_encode object
		hexEncObj := getGTKObject("btn_hex_encode", builder)
		if btnHexEncode, ok = hexEncObj.(*gtk.Button); ok {
			btnHexEncode.Connect("clicked", btnHexEncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(hexEncObj))
		}
		// get btn_hex_decode object
		hexDecObj := getGTKObject("btn_hex_decode", builder)
		if btnHexDecode, ok = hexDecObj.(*gtk.Button); ok {
			btnHexDecode.Connect("clicked", btnHexDecodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(hexDecObj))
		}
		// get btn_oct_encode object
		octEncObj := getGTKObject("btn_oct_encode", builder)
		if btnOctEncode, ok = octEncObj.(*gtk.Button); ok {
			btnOctEncode.Connect("clicked", btnOctEncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(octEncObj))
		}
		// get btn_oct_decode object
		octDecObj := getGTKObject("btn_oct_decode", builder)
		if btnOctDecode, ok = octDecObj.(*gtk.Button); ok {
			btnOctDecode.Connect("clicked", btnOctDecodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(octDecObj))
		}
		// get btn_b64_decode object
		b64DecodeObj := getGTKObject("btn_b64_decode", builder)
		if btnB64Dec, ok = b64DecodeObj.(*gtk.Button); ok {
			btnB64Dec.Connect("clicked", btnBase64DecodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(b64DecodeObj))
		}
		// get btn_b64_encode object
		b64EncodeObj := getGTKObject("btn_b64_encode", builder)
		if btnB64Enc, ok = b64EncodeObj.(*gtk.Button); ok {
			btnB64Enc.Connect("clicked", btnBase64EncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(b64EncodeObj))
		}
		// get btn_md5_encode object
		md5EncodeObj := getGTKObject("btn_md5_encode", builder)
		if btnMd5Encode, ok = md5EncodeObj.(*gtk.Button); ok {
			btnMd5Encode.Connect("clicked", btnMd5EncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(md5EncodeObj))
		}
		// get btn_sha1_encode object
		sha1EncodeObj := getGTKObject("btn_sha1_encode", builder)
		if btnSha1Encode, ok = sha1EncodeObj.(*gtk.Button); ok {
			btnSha1Encode.Connect("clicked", btnSha1EncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(sha1EncodeObj))
		}
		// get btn_sha256_encode object
		sha256EncodeObj := getGTKObject("btn_sha256_encode", builder)
		if btnSha256Encode, ok = sha256EncodeObj.(*gtk.Button); ok {
			btnSha256Encode.Connect("clicked", btnSha256EncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(sha256EncodeObj))
		}
		// get btn_sha512_encode object
		sha512EncodeObj := getGTKObject("btn_sha512_encode", builder)
		if btnSha512Encode, ok = sha512EncodeObj.(*gtk.Button); ok {
			btnSha512Encode.Connect("clicked", btnSha512EncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(sha512EncodeObj))
		}
		// get btn_url_encode object
		urlEncodeObj := getGTKObject("btn_url_encode", builder)
		if btnURLEnc, ok = urlEncodeObj.(*gtk.Button); ok {
			btnURLEnc.Connect("clicked", btnURLEncodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(urlEncodeObj))
		}
		// get btn_url_decode object
		urlDecodeObj := getGTKObject("btn_url_decode", builder)
		if btnURLDec, ok = urlDecodeObj.(*gtk.Button); ok {
			btnURLDec.Connect("clicked", btnURLDecodeClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(urlDecodeObj))
		}
		// get btn_clear object
		clearBtnObj := getGTKObject("btn_clear", builder)
		if btnClear, ok = clearBtnObj.(*gtk.Button); ok {
			btnClear.Connect("clicked", btnClearClicked)
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(clearBtnObj))
		}

		// get btn_exit object
		exitBtnObj := getGTKObject("btn_exit", builder)
		if btnExit, ok = exitBtnObj.(*gtk.Button); ok {
			btnExit.Connect("clicked", func () {
				// exits application
				app.Quit()
			})
		} else {
			log.Fatalln("error: not a button!\ntype: ", reflect.TypeOf(clearBtnObj))
		}

		// get entry_input object
		entryInput := getGTKObject("entry_input", builder)
		if entryInputTextView, ok = entryInput.(*gtk.TextView); ok {
		} else {
			log.Fatalln("error: not an entry component!\ntype: ", reflect.TypeOf(entryInput))
		}

		// get entry_output object
		entryOutput := getGTKObject("entry_output", builder)
		if entryOutputTextView, ok = entryOutput.(*gtk.TextView); ok {
		} else {
			log.Fatalln("error: not an entry component!\ntype: ", reflect.TypeOf(entryOutput))
		}
		

		// get window object
		winObj := getGTKObject("appWindow", builder)
		if win, ok := winObj.(*gtk.Window); ok {
			win.ShowAll() // renders all GUI components
			app.AddWindow(win)
		} else {
			log.Fatalln("error: not a window!\ntype: ", reflect.TypeOf(winObj))
		}
	})

	// run application
	app.Run(os.Args)

}
