package main

import (
	"encoding/json"
	"net"
	"os"

	"regexp"
	"time"

	"github.com/gocql/gocql"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
	"github.com/trustnetworks/firewall-messages"
)

const pgm = "alert-handler"

var timeFixRe *regexp.Regexp

type work struct {
	config   *gocql.ClusterConfig
	sess     *gocql.Session
	keyspace string
	fwURL    string
	fwConn   net.Conn
}

func (s *work) init() error {

	timeFixRe = regexp.MustCompile(`(\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d)\d+`)

	utils.Log("Initialising...")
	s.keyspace = utils.Getenv("CASSANDRA_KEYSPACE", "alerts")
	s.config = gocql.NewCluster()
	s.config.Hosts = []string{utils.Getenv("CASSANDRA_HOST", "cassandra")}

	// Open session to cassandra
	var err error
	for {
		s.sess, err = s.config.CreateSession()
		if err == nil {
			break
		}

		utils.Log("Could not create session: %s", err.Error())
		time.Sleep(time.Second * 5)
	}

	utils.Log("Connected.")

	// Create Keyspace (may already exist)
	utils.Log("Create keyspace '%s'...", s.keyspace)
	err = s.sess.Query(`
		CREATE KEYSPACE ` + s.keyspace + ` WITH REPLICATION = {
			'class': 'SimpleStrategy', 'replication_factor': '1'
		}`).Exec()
	if err != nil {
		utils.Log("keyspace error (ignored): %s", err.Error())
	}

	s.config.Keyspace = s.keyspace

	// Create session using the right keyspace
	for {
		s.sess, err = s.config.CreateSession()
		if err == nil {
			break
		}

		utils.Log("Could not create session: %s", err.Error())
		time.Sleep(time.Second * 5)
	}

	utils.Log("Connected to keyspace.")

	// Create Tables. This matches IoCAlert.
	// TODO: consider if this could be not hardcoded
	err = s.sess.Query(`
		CREATE TABLE dnsiocs (
			id uuid,
			timestamp Timestamp,
			devicename text,
			domainname text,
			sourceip text,
			starttime Timestamp,
			PRIMARY KEY (id)
		)
	`).Exec()
	if err != nil {
		utils.Log("Create error (ignored): %s", err.Error())
	}

	// Connect to firewall
	s.fwURL = utils.Getenv("FIREWALL_URL", "vpn-firewall-actions:64000")
	err = s.fwConnect()
	if err != nil {
		utils.Log("Firewall connect error: %s", err.Error())
		return err
	}
	utils.Log("Connected to firewall")

	return nil
}

func (s *work) fwConnect() error {
	attempts := 0

	// try to connect 3 times, after that error
	var err error
	for attempts < 3 {
		attempts++
		s.fwConn, err = net.Dial("tcp", s.fwURL)
		if err != nil {
			utils.Log("Couldn't connect to url (attempt %d): %s",
				attempts, err.Error())
			if attempts == 3 {
				utils.Log("Unable to connect after 3 attempts exiting...")
				return err
			}
			time.Sleep(time.Second * 3) // wait for a bit
		}
	}

	return nil
}

type alertInfo struct {
	Action string
	Device string
	Time   time.Time
	Value  string
	SrcIp  net.IP
}

func sendEvent(alert alertInfo, w *worker.Worker) error {
	ioc := dt.Indicator{Type: alert.Action, Value: alert.Value,
		Author: "TrustNetworks", Source: "TN analytics"}
	iocs := []*dt.Indicator{&ioc}
	src := []string{alert.SrcIp.String()}
	event := dt.Event{Id: "", Action: alert.Action, Device: alert.Device,
		Time: alert.Time.Format("2006-01-02T15:04:05.000Z"), Indicators: &iocs,
		Src: src}
	jEvent, err := json.Marshal(event)
	if err != nil {
		utils.Log("JSON marshal error: %s", err.Error())
		return err
	}
	w.Send("output", jEvent)
	return nil
}

func (s *work) Handle(msg []uint8, w *worker.Worker) error {

	// DEBUG
	utils.Log("DEBUG: Received: " + string(msg))

	// Unmarshall IOC Alert
	var iocAlert dt.IoCAlert
	err := json.Unmarshal(msg, &iocAlert)
	if err != nil {
		utils.Log("Couldn't unmarshal json: %s",
			err.Error())
		return nil
	}

	if iocAlert.Type == dt.IoCDnsCat2 {
		// Unmarshall DNS Alert
		var dnsAlert dt.DNSIoCAlert
		err := json.Unmarshal([]byte(iocAlert.Data), &dnsAlert)
		if err != nil {
			utils.Log("Couldn't unmarshal json: %s",
				err.Error())
			return nil
		}

		// Copy ID and timestamp into the DNS record we are going to store
		dnsAlert.ID = iocAlert.ID
		dnsAlert.Timestamp = iocAlert.Timestamp

		dnsAlertJSON, err := json.Marshal(dnsAlert)
		if err != nil {
			utils.Log("JSON marshal error: %s", err.Error())
		} else {
			// Remove time digits down to millisecs so Cassandra can handle them
			dnsAlertJSONStr := string(dnsAlertJSON)
			dnsAlertJSONStr = timeFixRe.ReplaceAllString(dnsAlertJSONStr, "$1")

			// Store alert
			err = s.sess.Query(
				"INSERT INTO dnsiocs JSON '" + dnsAlertJSONStr + "'").Exec()
			if err != nil {
				utils.Log("Store error: %s", err.Error())
			}
		}

		// Tell firewall to block this DNS tunnel
		var fwMessage firewall.Message
		fwMessage.Action = firewall.DNSTunnelAction
		fwMessage.BDTValue.Hostname = dnsAlert.DomainName
		err = s.sendFirewallMessage(fwMessage)
		if err != nil {
			utils.Log("Error sending firewall message: %s", err.Error())
		}

		// TODO store this firewall action

		// send an event so it ends in the relevant end repos
		eventInfo := alertInfo{"DNS-tunnel", dnsAlert.DeviceName,
			iocAlert.Timestamp, dnsAlert.DomainName,
			dnsAlert.SourceIP}
		sendEvent(eventInfo, w)
	} else {
		utils.Log("Unrecognised IoCAlert type (ignoring): %d", iocAlert.Type)
	}

	// DEBUG
	//fmt.Println(string(msg))

	return nil
}

func (s *work) sendFirewallMessage(msg firewall.Message) error {

	utils.Log("DEBUG: sending message to firewall")

	// Marshall message to json byte array
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		utils.Log("Could not create json representation of firewall message: %s",
			err.Error())
		return err
	}

	// add newline character to seperate messages
	jsonMsg = append(jsonMsg, '\n')

	_, writeErr := s.fwConn.Write(jsonMsg)
	if writeErr != nil {
		utils.Log("Could not send message, try to reconnect")

		// Disconnect
		s.fwConn.Close()

		// Reconnect (will try three times)
		err = s.fwConnect()
		if err != nil {
			utils.Log("Failed to reconnect")
			return err
		}

		utils.Log("Managed to reconnect, trying to resend message")
		_, writeErr2 := s.fwConn.Write(jsonMsg)
		if writeErr2 != nil {
			utils.Log("resend failed")
			return writeErr2
		}
	}

	return nil
}

func (s *work) close() {
	s.sess.Close()
}

func (s *work) fwClose() {
	s.fwConn.Close()
}

func main() {
	var w worker.QueueWorker
	var s work
	utils.LogPgm = pgm

	// Initialise
	utils.Log("Initialising...")
	err := s.init()
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}
	defer s.close()
	defer s.fwClose()

	var input string
	var output []string

	if len(os.Args) > 1 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}

	err = w.Initialise(input, output, pgm)
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	utils.Log("Initialisation complete.")

	w.Run(&s)
}
