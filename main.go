package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "math/rand"
    "net"
    "strings"
    "time"
)

var recordTypes = map[uint16]string{
    1: "A",
    2: "NS",
    5: "CNAME",
}

type DnsHeader struct {
    queryId       uint16
    flags         uint16
    numQuestions  uint16
    numAnswers    uint16
    numAuth       uint16
    numAdditional uint16
}

type DnsQuery struct {
    domain     string
    queryType  uint16
    queryClass uint16
}

type DnsRecord struct {
    name          string
    recordType    uint16
    recordTypeStr string
    recordClass   uint16
    ttl           uint32
    rdLength      uint16
    cName         string
    rData         []byte
    ip            []byte
}

type DnsResponse struct {
    header      DnsHeader
    queries     []DnsQuery
    answers     []DnsRecord
    authorities []DnsRecord
    additionals []DnsRecord
}

func (resp *DnsResponse) parse(respRaw []byte) {
    resp.header = DnsHeader{}
    resp.header.parse(respRaw[:12])
    resp.queries = make([]DnsQuery, 0)
    resp.answers = make([]DnsRecord, 0)
    resp.authorities = make([]DnsRecord, 0)
    resp.additionals = make([]DnsRecord, 0)

    respReader := bytes.NewReader(respRaw)
    respReader.Seek(12, io.SeekStart)
    for i := uint16(0); i < resp.header.numQuestions; i++ {
        newQuery := DnsQuery{}
        newQuery.parse(respReader)
        resp.queries = append(resp.queries, newQuery)
    }

    for i := uint16(0); i < resp.header.numAnswers; i++ {
        newAnswer := DnsRecord{}
        newAnswer.parse(respReader)
        resp.answers = append(resp.answers, newAnswer)
    }
    for i := uint16(0); i < resp.header.numAuth; i++ {
        newAuth := DnsRecord{}
        newAuth.parse(respReader)
        resp.authorities = append(resp.authorities, newAuth)
    }
    for i := uint16(0); i < resp.header.numAdditional; i++ {
        newAdditional := DnsRecord{}
        newAdditional.parse(respReader)
        resp.additionals = append(resp.additionals, newAdditional)
    }
}

func (q *DnsQuery) parse(resp *bytes.Reader) {
    q.domain = parseDomainName(resp)
    buf := make([]byte, 2)

    resp.Read(buf)
    q.queryType = binary.BigEndian.Uint16(buf)

    resp.Read(buf)
    q.queryClass = binary.BigEndian.Uint16(buf)
}

func (r *DnsRecord) parse(resp *bytes.Reader) {
    r.name = parseDomainName(resp)
    buf := make([]byte, 2)

    resp.Read(buf)
    r.recordType = binary.BigEndian.Uint16(buf)

    resp.Read(buf)
    r.recordClass = binary.BigEndian.Uint16(buf)

    buf = make([]byte, 4)
    resp.Read(buf)
    r.ttl = binary.BigEndian.Uint32(buf)

    buf = make([]byte, 2)
    resp.Read(buf)

    r.rdLength = binary.BigEndian.Uint16(buf)
    r.rData = make([]byte, r.rdLength)

    r.readRecordData(resp)
}

func (d *DnsHeader) parse(resp []byte) {
    d.queryId = binary.BigEndian.Uint16(resp[:2])
    d.flags = binary.BigEndian.Uint16(resp[2:4])
    d.numQuestions = binary.BigEndian.Uint16(resp[4:6])
    d.numAnswers = binary.BigEndian.Uint16(resp[6:8])
    d.numAuth = binary.BigEndian.Uint16(resp[8:10])
    d.numAdditional = binary.BigEndian.Uint16(resp[10:12])
}

func (d *DnsHeader) encode() []byte {
    nums := []uint16{
        d.queryId,
        0x0120,
        0x0001,
        0x0000,
        0x0000,
        0x0000,
    }
    headerBytes := make([]byte, 0)
    buf := make([]byte, 2)

    for _, num := range nums {
        binary.BigEndian.PutUint16(buf, num)
        headerBytes = append(headerBytes, buf...)
    }
    return headerBytes
}

func (r *DnsRecord) readRecordData(respReader *bytes.Reader) {
    if rt, exists := recordTypes[r.recordType]; exists {
        r.recordTypeStr = rt
    }

    switch r.recordTypeStr {
    case "CNAME", "NS":
        r.cName = parseDomainName(respReader)
    case "A":
        r.ip = make([]byte, 4)
        respReader.Read(r.ip)

        // fmt.Printf("IP = %d.%d.%d.%d\n", r.ip[0], r.ip[1], r.ip[2], r.ip[3])
    }
}

func encodeDomain(domain string) []byte {
    domainBytes := make([]byte, 0)

    names := strings.Split(domain, ".")
    for _, name := range names {
        domainBytes = append(domainBytes, uint8(len(name)))
        domainBytes = append(domainBytes, []byte(name)...)
    }
    domainBytes = append(domainBytes, 0x00)
    return domainBytes
}

func makeDnsQuery(domain string, queryType uint16) []byte {
    queryHeader := DnsHeader{}
    rand.Seed(time.Now().UnixNano())
    queryHeader.queryId = uint16(rand.Intn(65536))

    header := queryHeader.encode()

    typeAndClass := make([]byte, 2)
    binary.BigEndian.PutUint16(typeAndClass, queryType)

    typeAndClass = append(typeAndClass, 0x00, 0x01)
    question := append(encodeDomain(domain), typeAndClass...)

    headerAndQ := append(header, question...)
    return headerAndQ
}

// parseDomainName parses the domain name(s) in the
// DNS response.
// Precondition: The header bytes have already been skipped over
func parseDomainName(respReader *bytes.Reader) string {
    domainNames := make([]string, 0)

    for {
        length, err := respReader.ReadByte()
        if err != nil {
            if errors.As(err, io.EOF) {
                break
            }
            panic("cannot read length")
        }

        if length == 0 {
            break // end of name
        }

        if length&0b11000000 == 0b11000000 { // DNS compression
            secondByte, err := respReader.ReadByte()
            if err != nil {
                panic("cannot read second byte in domain name compression")
            }
            offSet := ((uint16(length) & 0x3f) << 8) + uint16(secondByte)
            curPos, err := respReader.Seek(0, io.SeekCurrent)
            if err != nil {
                panic("Cannot get current position")
            }
            _, err = respReader.Seek(int64(offSet), io.SeekStart)
            if err != nil {
                panic("Cannot seek to name compression offset")
            }
            domainNames = append(domainNames, parseDomainName(respReader))
            respReader.Seek(curPos, io.SeekStart)
            break
        } else {
            domainBytes := make([]byte, length)
            numRead, err := respReader.Read(domainBytes)
            if err != nil || numRead != int(length) {
                panic(fmt.Errorf("not able to read %d amount of bytes in domain", int(length)))
            }
            domainNames = append(domainNames, string(domainBytes))
        }
    }
    return strings.Join(domainNames, ".")
}

func main() {
    nameFlag := flag.String("n", "", "the domain name")
    flag.Parse()

    if *nameFlag == "" {
        return
    }
    dnsServerHost := "8.8.8.8"
    dnsServerPort := "53"

    // fmt.Println(encodeDomain("google.com"))

    conn, err := net.Dial("udp", dnsServerHost+":"+dnsServerPort)

    if err != nil {
        panic("Cannot send UDP request")
    }
    // payloadStr := "a3270120000100000000000106676f6f676c6503636f6d00000100010000291000000000000000"
    // payloadStr := "a3270120000100000000000106676f6f676c6503636f6d0000010001"

    payloadBytes := makeDnsQuery(*nameFlag, 1)
    // fmt.Println("===============Comparison==============")
    // fmt.Println(payloadStr)
    // fmt.Printf("%x\n", payloadBytes)
    // fmt.Println("=======================================")

    // fmt.Println("Writing to conn")
    _, err = conn.Write(payloadBytes)
    //  fmt.Println("Done writing to conn")
    if err != nil {
        panic("Writing to connection")
    }
    buf := make([]byte, 1024)

    // fmt.Println("Reading from conn")
    respLength, err := conn.Read(buf)
    if err != nil {
        panic("Reading from connection")
    }
    // fmt.Println("Done reading from conn")

    buf = buf[:respLength] // truncate the response
    resp := DnsResponse{}

    resp.parse(buf)

    for _, answer := range resp.answers {
        fmt.Printf("%s    %d    %s    ", answer.name, answer.ttl, answer.recordTypeStr)
        if answer.recordTypeStr == "CNAME" || answer.recordTypeStr == "NS" {
            fmt.Printf("%s", answer.cName)
        } else if answer.recordTypeStr == "A" && len(answer.ip) > 0 {
            fmt.Printf("%d.%d.%d.%d", answer.ip[0], answer.ip[1], answer.ip[2], answer.ip[3])
        }
        fmt.Println()
    }
}
