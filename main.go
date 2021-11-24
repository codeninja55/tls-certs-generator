package main

import (
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Config struct {
	// CertType can either be 'client' or 'server'
	CertType string
	// Days is the number of days for validity
	Days string
	// Sans is additional subject alternative names to add to the CSR signing
	Sans MultiString
	// Subject is the additional inf
	Subject string
	// OutDir is the path of where to write the final certificates
	OutDir string
	// EnvVarPath is the path to read the .env file from
	EnvVarPath string
}

const (
	SHELL = "/bin/bash"

	caCertsDir           = "certificate-authority"
	caPrivateKeyName     = "ca-key.pem"
	caSelfSignedCertName = "ca-cert.pem"
)

var (
	flags = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	help         = flags.Bool("help", false, prettify("print the usage instructions and exit."))
	verbose      = flags.Bool("verbose", false, prettify(`enable verbose output.`))
	printVersion = flags.Bool("version", false, prettify(`print version.`))

	cfg Config

	version = "dev build <no version set>"

	// These are stored in the current dir to ensure we know where they are during signing
	caPrivateKey  = fmt.Sprintf("%s/%s", caCertsDir, caPrivateKeyName)
	caCertificate = fmt.Sprintf("%s/%s", caCertsDir, caSelfSignedCertName)
)

func init() {
	flags.Var(&cfg.Sans, "san", prettify(`
		a subject alternative names URI seperated by to add to the certificate. Use the flag multiple times to add more
		than one SAN, e.g. -san "example.com" -san "*.example.com".`))
	flags.StringVar(&cfg.CertType, "type", "client", prettify(`
		the type of certificate, i.e. either [client | server].`))
	flags.StringVar(&cfg.Days, "days", "365", prettify(`
		the number of days the certificate is valid.`))
	flags.StringVar(&cfg.OutDir, "out-dir", "certificates", prettify(`
		the final destination for the certificates.`))
	flags.StringVar(&cfg.EnvVarPath, "dot-env", ".env", prettify(`
		the path to the .env file to read from.`))
	flags.StringVar(&cfg.Subject, "subject", "", prettify(`
		the additional subject information to pass automatically. Can also use .env file or pass the environment 
		variable "TLS_GEN_SUBJECT". The environment variable will override what is passed in the command.`))
}

func main() {
	flags.Usage = usage

	if err := flags.Parse(os.Args[2:]); err != nil {
		fmt.Printf("parse flags with error: %v", err)
		os.Exit(1)
	}

	if *help {
		usage()
		os.Exit(0)
	}

	if *printVersion {
		fmt.Fprintf(os.Stderr, "%s %s\n", os.Args[0], version)
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	err := godotenv.Load(cfg.EnvVarPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s into environment: %v", cfg.EnvVarPath, err)
		os.Exit(1)
	}

	if cfg.Subject == "" {
		cfg.Subject = os.Getenv("TLS_GEN_SUBJECT")
	}

	if strings.HasSuffix(cfg.OutDir, "/") {
		cfg.OutDir = strings.TrimRight(cfg.OutDir, "/")
	}

	if strings.HasPrefix(cfg.OutDir, "~") {
		home := os.Getenv("HOME")
		if home != "" {
			cfg.OutDir = fmt.Sprintf("%s%s", home, strings.TrimLeft(cfg.OutDir, "~"))
		}
	}

	if *verbose {
		logInfof("%+v", cfg)
	}

	switch os.Args[1] {
	case "ca":
		generateCA()
	case "cert":
		if err := existsOrCreateDir(cfg.OutDir); err != nil {
			fmt.Fprintf(os.Stderr, "error creating %s directory: %v", cfg.OutDir, err)
			os.Exit(1)
		}

		generateCert()
		signCertificateSigningRequest()
		if *verbose {
			printCertificateDetails()
			verifyCertificate()
		}
	default:
		usage()
		os.Exit(1)
	}
}

/*============================== OPENSSL COMMANDS ==============================*/

// generateCA creates a self-signed Certificate Authority certificate and private key.
func generateCA() {
	_ = existsOrCreateDir(caCertsDir)

	if *verbose {
		logInfof("Creating private key and self-signed certificate for Certificate Authority in %s", caCertsDir)
	}
	cmd := []string{
		"openssl",
		"req",
		"-x509",
		"-newkey rsa:4096",
		"-sha256",
		"-nodes",
		fmt.Sprintf("-days %s", cfg.Days),
		fmt.Sprintf("%s %s", "-keyout", caPrivateKey),
		fmt.Sprintf("%s %s", "-out", caCertificate),
	}

	if cfg.Subject != "" {
		cmd = append(cmd, fmt.Sprintf("-subj \"%s\"", cfg.Subject))
	}

	runExecWithOutput(cmd)
}

func generateCert() {
	_ = existsOrCreateDir(cfg.OutDir)

	if *verbose {
		logInfof("Creating %s certificate for %s in %s", cfg.CertType, cfg.OutDir)
	}
	cmd := []string{
		"openssl",
		"req",
		"-newkey rsa:4096",
		"-sha256",
		"-nodes",
		fmt.Sprintf("-keyout %s/%s-key.pem", cfg.OutDir, cfg.CertType),
		fmt.Sprintf("-out %s/%s-csr.pem", cfg.OutDir, cfg.CertType),
	}

	if cfg.Subject != "" {
		cmd = append(cmd, fmt.Sprintf("-subj \"%s\"", cfg.Subject))
	}

	runExecWithOutput(cmd)
}

func signCertificateSigningRequest() {
	if *verbose {
		logInfof("Signing the %s certificate for %s with %s\n", cfg.CertType, caCertificate)
	}
	cmd := []string{
		"openssl",
		"x509",
		"-req",
		fmt.Sprintf("-in %s/%s-csr.pem", cfg.OutDir, cfg.CertType),
		"-CAform PEM",
		fmt.Sprintf("-CA %s", caCertificate),
		"-CAkeyform PEM",
		fmt.Sprintf("-CAkey %s", caPrivateKey),
		"-CAcreateserial",
		fmt.Sprintf("-out %s/%s-cert.pem", cfg.OutDir, cfg.CertType),
		fmt.Sprintf("-days %s", cfg.Days),
	}

	if cfg.Subject != "" {
		cmd = append(cmd, fmt.Sprintf("-subj \"%s\"", cfg.Subject))
	}

	if len(cfg.Sans) > 0 {
		cmd = append(cmd, fmt.Sprintf("-extfile <(printf \"%s\")", generateSubjectAltName()))
		//cmd = append(cmd, "-extfile ./ext.cnf")
	}

	runExecWithOutput(cmd)
}

// generateSubjectAltName returns the subject alternative name for either a file or direct input on CLI.
func generateSubjectAltName() string {
	var sanOut []string

	for _, s := range cfg.Sans {
		if strings.Contains(s, "DNS:") {
			sanOut = append(sanOut, s)
		} else {
			sanOut = append(sanOut, fmt.Sprintf("DNS:%s", s))
		}
	}

	// Append the localhost IP to allow using locally
	sanOut = append(sanOut, "IP:127.0.0.1")
	sanOut = append(sanOut, "IP:0.0.0.0")
	sanResult := fmt.Sprintf("subjectAltName=%s", strings.Join(sanOut, ","))
	if *verbose {
		logInfof("Adding subject alternative names: %s", sanResult)
	}
	return sanResult
}

func printCertificateDetails() {
	logInfof("%s certificate at %s\n", cfg.CertType, cfg.OutDir)
	cmd := []string{
		"openssl",
		"x509",
		fmt.Sprintf("-in %s/%s-cert.pem", cfg.OutDir, cfg.CertType),
		"-noout",
		"-text",
	}

	runExecWithOutput(cmd)
}

func verifyCertificate() {

	fmt.Printf("Verifying the %s certificate with %s", cfg.CertType, caCertificate)
	cmd := []string{
		"openssl",
		"verify",
		fmt.Sprintf("-CAfile %s", caCertificate),
		fmt.Sprintf("%s/%s-cert.pem", cfg.OutDir, cfg.CertType),
	}

	runExecWithOutput(cmd)
}

/*============================== HELPER FUNCTIONS ==============================*/

func runExecWithOutput(commands []string) {
	cmdStr := strings.Join(commands, " ")
	cmd := exec.Command(SHELL, "-c", cmdStr)

	if *verbose {
		logInfof("command: %s", cmd)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		err := fmt.Errorf("failed to run command: %s", cmd)
		fail(err, err.Error())
	}
}

func existsOrCreateDir(dir string) error {
	f, err := os.Stat(dir)
	if err != nil {
		if mkdirErr := os.Mkdir(dir, 0755); mkdirErr != nil {
			fail(mkdirErr, "unable to create directory %s", dir)
		}
		return nil
	}

	switch mode := f.Mode(); {
	case mode.IsDir():
		return nil
	case mode.IsRegular():
		err := fmt.Errorf("the path %s is not a directory", dir)
		fail(err, err.Error())
	}
	return nil
}

func usage() {
	_, err := fmt.Fprintf(os.Stderr, `TLS Certs Generator
Usage: %s [command] [options]

Generate a TLS certificate for us locally with the same Certificate Authority for 
both client and server so that mutual TLS can be used.

Available Commands:
  ca     generate a certificate authority self-signed.
  cert   generate server or client certificates and sign it with the CA.
Available Options:
`, os.Args[0])

	flags.PrintDefaults()
	if err != nil {
		return
	}
}

func prettify(docString string) string {
	parts := strings.Split(docString, "\n")
	// cull empty lines and also remove trailing and leading spaces from each line

	i := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts[i] = part
		i++
	}

	return strings.Join(parts[:i], "\n"+"")
}

type MultiString []string

func (m *MultiString) String() string {
	return strings.Join(*m, ",")
}

func (m *MultiString) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func warn(msg string, args ...interface{}) {
	msg = fmt.Sprintf("Warning: %s\n", msg)
	fmt.Fprintf(os.Stderr, msg, args...)
}

func fail(err error, msg string, args ...interface{}) {
	if err != nil {
		msg += ": %v"
		args = append(args, err)
	}
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		os.Exit(1)
	} else {
		// nil error means it was CLI usage issue
		fmt.Fprintf(os.Stderr, "Try '%s -help' for more details.\n", os.Args[0])
		os.Exit(2)
	}
}

func logErrorf(format string, args ...interface{}) {
	prefix := "ERROR: " + time.Now().Format("2021-02-01 15:04:05") + " "
	fmt.Printf(prefix+format+"\n", args...)
}

func logInfof(format string, args ...interface{}) {
	prefix := "INFO: " + time.Now().Format("2021-02-01 15:04:05") + " "
	fmt.Printf(prefix+format+"\n", args...)
}
