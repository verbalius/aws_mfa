package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

// isFlagError returns true when an error likely indicates a bad flag or usage issue.
func isFlagError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// common pflag/cobra parse error messages
	if strings.Contains(s, "unknown flag") || strings.Contains(s, "unknown shorthand flag") || strings.Contains(s, "flag needs an argument") || strings.Contains(s, "invalid value") || strings.Contains(s, "invalid argument") {
		return true
	}
	return false
}

// isMfaError attempts to detect an error returned by STS that indicates a bad/expired MFA code.
func isMfaError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// check for common phrases or AWS error codes indicating invalid MFA/auth code
	if strings.Contains(s, "invalidauthenticationcode") || strings.Contains(s, "invalid authentication code") {
		return true
	}
	if strings.Contains(s, "authentication code") || strings.Contains(s, "mfa") && strings.Contains(s, "invalid") {
		return true
	}
	if strings.Contains(s, "invalid token") || strings.Contains(s, "invalid code") {
		return true
	}
	return false
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))
var version = "dev"

func main() {
	var createFlag bool
	var profilesFlag bool
	var autoFlag bool
	var installCompFlag bool

	rootCmd := &cobra.Command{
		Use:     "aws_mfa [profile]",
		Short:   "🤖 Manage MFA-enabled AWS profiles and obtain session tokens",
		Args:    cobra.MaximumNArgs(1),
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if installCompFlag {
				return installCompletion(cmd)
			}
			if createFlag {
				return cmdCreate()
			}
			if profilesFlag {
				profiles, err := profilesWithMFA()
				if err != nil {
					return err
				}
				for _, p := range profiles {
					fmt.Println(p)
				}
				return nil
			}
			if len(args) > 0 {
				return cmdAuth(args[0])
			}
			if autoFlag || len(os.Args) == 1 {
				profile := os.Getenv("AWS_PROFILE")
				if profile == "" {
					return fmt.Errorf("AWS_PROFILE not set; see --help")
				}
				return cmdAuth(profile)
			}
			return cmd.Help()
		},
	}

	rootCmd.Flags().BoolVar(&createFlag, "create", false, "guided creation of a profile with MFA")
	rootCmd.Flags().BoolVar(&profilesFlag, "profiles", false, "list profiles that have MFA configured (for shell completion)")
	rootCmd.Flags().BoolVar(&autoFlag, "auto", false, "(default) use $AWS_PROFILE for authentication when set")
	rootCmd.Flags().BoolVar(&installCompFlag, "install-completion", false, "install shell completion for your current shell")

	// Don't show usage on every error; only show for flag/usage errors
	rootCmd.SilenceUsage = true
	// silence cobra's automatic error printing so we control output formatting
	rootCmd.SilenceErrors = true
	if err := rootCmd.Execute(); err != nil {
		if isFlagError(err) {
			_ = rootCmd.Usage()
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

}

func cmdCreate() error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Profile name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("🤨 Profile name required")
	}
	fmt.Print("AWS Access Key ID: ")
	ak, _ := reader.ReadString('\n')
	ak = strings.TrimSpace(ak)
	fmt.Print("AWS Secret Access Key: ")
	sk, _ := reader.ReadString('\n')
	sk = strings.TrimSpace(sk)
	fmt.Print("Region (optional): ")
	region, _ := reader.ReadString('\n')
	region = strings.TrimSpace(region)
	fmt.Print("MFA device ARN (e.g. arn:aws:iam::123456789012:mfa/you): ")
	mfa, _ := reader.ReadString('\n')
	mfa = strings.TrimSpace(mfa)

	if ak == "" || sk == "" || mfa == "" {
		return errors.New("🤓 access key, secret and mfa arn are required")
	}

	if err := ensureAWSDir(); err != nil {
		return err
	}
	// write static creds to <name>-origin
	originName := name + "-origin"
	if err := writeCredentialsSection(originName, map[string]string{
		"aws_access_key_id":     ak,
		"aws_secret_access_key": sk,
	}); err != nil {
		return err
	}
	// write config profile section for <name>-origin
	cfgKey := "profile " + originName
	cfg := map[string]string{}
	if region != "" {
		cfg["region"] = region
	}
	cfg["mfa_serial"] = mfa
	if err := writeConfigSection(cfgKey, cfg); err != nil {
		return err
	}
	fmt.Println("📝 Profile created:", name)
	fmt.Printf("Now run `aws_mfa %s` to obtain session credentials using MFA.\n", name)
	return nil
}
func cmdAuth(profile string) error {
	// always use <profile>-origin as the API profile (must contain static credentials)
	origProfile := profile + "-origin"

	// read credentials and config profiles
	existOrig, err := readCredentialsSection(origProfile)
	if err != nil {
		return err
	}
	existProfile, err := readCredentialsSection(profile)
	if err != nil {
		return err
	}

	cfgSection := "profile " + profile
	origCfgSection := "profile " + origProfile
	existOrigCfg, err := readConfigSection(origCfgSection)
	if err != nil {
		return err
	}
	existCfg, err := readConfigSection(cfgSection)
	if err != nil {
		return err
	}

	// determine mfa_serial: prefer config for profile, fall back to profile-origin
	var mfa string
	if v, ok := existCfg["mfa_serial"]; ok && v != "" {
		mfa = v
	} else if v, ok := existOrigCfg["mfa_serial"]; ok && v != "" {
		mfa = v
	}
	if mfa == "" {
		return errors.New("no mfa_serial configured for profile or its origin: " + profile)
	}

	apiProfile := origProfile
	if len(existOrig) == 0 {
		// no orig present: if profile has static creds (no session token), move it to orig
		if len(existProfile) > 0 {
			if _, hasSession := existProfile["aws_session_token"]; !hasSession {
				// move profile -> profile-original
				if err := writeCredentialsSection(origProfile, existProfile); err != nil {
					return err
				}
				if err := deleteCredentialsSection(profile); err != nil {
					return err
				}
				// move config section as well if present
				if len(existOrigCfg) == 0 && len(existCfg) > 0 {
					if err := writeConfigSection(origCfgSection, existCfg); err != nil {
						return err
					}
					if err := deleteConfigSection(cfgSection); err != nil {
						return err
					}
					// update existOrigCfg to moved config
					existOrigCfg = existCfg
				}
				// now apiProfile is origProfile
			} else {
				return fmt.Errorf("profile %s contains only session credentials and %s not found; restore original static credentials before calling auth", profile, origProfile)
			}
		} else {
			return fmt.Errorf("no static credentials found for %s or %s; create a profile with static creds first", profile, origProfile)
		}
	}

	// show connecting log and verify connectivity using GetCallerIdentity with the orig profile
	fmt.Fprintln(os.Stderr, "🔌 Connecting to AWS...")
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(apiProfile))
	if err != nil {
		return fmt.Errorf("failed to load AWS config for profile %s: %v", apiProfile, err)
	}
	client := sts.NewFromConfig(cfg)
	if _, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return fmt.Errorf("failed to contact AWS STS (check profile credentials/network): %v", err)
	}

	// prompt for token with emoji after confirming connectivity (profile name colored orange and underlined)
	var outResp *sts.GetSessionTokenOutput
	var code string
	reader := bufio.NewReader(os.Stdin)
	// allow one retry if the MFA code was incorrect
	for attempt := 1; attempt <= 2; attempt++ {
		fmt.Printf("🙈 Enter MFA token for \x1b[4;38;5;208m%s\x1b[0m: ", profile)
		c, _ := reader.ReadString('\n')
		code = strings.TrimSpace(c)
		if attempt == 1 && code == "" {
			fmt.Println("🤨 You OK? MFA token is required. Let's try this again..")
			continue
		}

		in := &sts.GetSessionTokenInput{
			SerialNumber:    aws.String(mfa),
			TokenCode:       aws.String(code),
			DurationSeconds: aws.Int32(129600),
		}
		outResp, err = client.GetSessionToken(ctx, in)
		if err == nil {
			break
		}
		// if this looks like an MFA/authentication code error and we haven't retried yet, prompt again
		if attempt == 1 && isMfaError(err) {
			fmt.Fprintln(os.Stderr, "🫨 Invalid MFA token, try again")
			continue
		}
		return fmt.Errorf("🤔 Failed to get session token: %v", err)
	}
	if outResp == nil || outResp.Credentials == nil || outResp.Credentials.AccessKeyId == nil {
		return errors.New("no credentials returned from STS")
	}
	resp := outResp

	// write session credentials into the original profile name
	if err := ensureAWSDir(); err != nil {
		return err
	}
	if err := writeCredentialsSection(profile, map[string]string{
		"aws_access_key_id":     *resp.Credentials.AccessKeyId,
		"aws_secret_access_key": *resp.Credentials.SecretAccessKey,
		"aws_session_token":     *resp.Credentials.SessionToken,
	}); err != nil {
		return err
	}

	// ensure config: create/update [profile <profile>] with mfa_serial (and preserve region if available)
	cfgToWrite := map[string]string{"mfa_serial": mfa}
	if r, ok := existOrigCfg["region"]; ok && r != "" {
		cfgToWrite["region"] = r
	}
	if err := writeConfigSection(cfgSection, cfgToWrite); err != nil {
		return err
	}

	// pick a random green emoji for success
	green := []string{"🌿", "🐸", "🐢", "🍃", "🥑", "🌵", "🥝", "🐉", "🥦", "🦎", "🥬", "🌲", "🥒", "🐛", "🎄"}
	e := green[rng.Intn(len(green))]
	fmt.Printf("%s MFA profile configured. To use in shell run `export AWS_PROFILE=%s`\n", e, profile)
	return nil
}

// installCompletion generates and installs simple shell completion that
// only suggests available MFA-enabled profiles (no flags).
func installCompletion(cmd *cobra.Command) error {
	shellEnv := os.Getenv("SHELL")
	shell := filepath.Base(shellEnv)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var dest string
	var content string
	switch {
	case strings.Contains(shell, "zsh"):
		dir := filepath.Join(home, ".zsh", "completions")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		// zsh: use aws_mfa --profiles to supply completions
		content = `#compdef aws_mfa
_aws_mfa() {
	local -a profiles
	profiles=("${(@f)$(aws_mfa --profiles)}")
	_describe 'profiles' profiles
}
_arguments '*:profile:_aws_mfa'
`
		dest = filepath.Join(dir, "_aws_mfa")
	case strings.Contains(shell, "fish"):
		dir := filepath.Join(home, ".config", "fish", "completions")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		// fish: use command substitution to produce completions
		content = "complete -c aws_mfa -f -a \"(aws_mfa --profiles)\"\n"
		dest = filepath.Join(dir, "aws_mfa.fish")
	case strings.Contains(shell, "bash"):
		dir := filepath.Join(home, ".local", "share", "bash-completion", "completions")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		// bash: use compgen with aws_mfa --profiles
		content = `#!/bin/bash
_aws_mfa() {
	local cur
	cur="${COMP_WORDS[COMP_CWORD]}"
	COMPREPLY=( $(compgen -W "$(aws_mfa --profiles)" -- "$cur") )
}
complete -F _aws_mfa aws_mfa
`
		dest = filepath.Join(dir, "aws_mfa")
	default:
		fmt.Printf("shell not detected or unsupported; supported shells are bash, zsh, fish\n")
		return nil
	}

	if err := os.WriteFile(dest, []byte(content), 0644); err != nil {
		return err
	}
	fmt.Printf("wrote completion to %s\n", dest)

	// let's read the .zshrc/.bashrc/.config/fish/config.fish and suggest adding source line if not present
	var rcPath string
	var sourceLine string
	switch {
	case strings.Contains(shell, "zsh"):
		rcPath = filepath.Join(home, ".zshrc")
		sourceLine = fmt.Sprintf("fpath+=%s\nautoload -Uz compinit\ncompinit\n", filepath.Dir(dest))
	case strings.Contains(shell, "bash"):
		rcPath = filepath.Join(home, ".bashrc")
		sourceLine = fmt.Sprintf("source %s\n", dest)
	case strings.Contains(shell, "fish"):
		rcPath = filepath.Join(home, ".config", "fish", "config.fish")
		sourceLine = fmt.Sprintf("source %s\n", dest)
	}
	if rcPath != "" {
		// let's add it ourselves if not already present
		b, err := os.ReadFile(rcPath)
		if err == nil {
			if !strings.Contains(string(b), dest) {
				f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := f.WriteString("\n# aws_mfa completion\n" + sourceLine); err != nil {
					return err
				}
				fmt.Printf("added source line to %s\n", rcPath)
			} else {
				fmt.Printf("source line already present in %s; no changes made\n", rcPath)
			}
		}
	}
	// advice user to restart shell
	fmt.Println("please restart your shell or source your rc file to enable completions")
	fmt.Printf("run: `source %s` \n", rcPath)
	return nil
}

// helpers
func awsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws")
}

func ensureAWSDir() error {
	dir := awsDir()
	return os.MkdirAll(dir, 0700)
}

func credentialsPath() string {
	return filepath.Join(awsDir(), "credentials")
}

func configPath() string {
	return filepath.Join(awsDir(), "config")
}

// (removed unused helper findMfaSerial)

func profilesWithMFA() ([]string, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	var cur string
	var curHasMfa bool
	for _, l := range lines {
		l2 := strings.TrimSpace(l)
		if strings.HasPrefix(l2, "[") && strings.HasSuffix(l2, "]") {
			if cur != "" && curHasMfa {
				out = append(out, cur)
			}
			curHasMfa = false
			cur = strings.TrimSpace(l2[1 : len(l2)-1])
			// normalize 'profile name' to 'name'
			if strings.HasPrefix(cur, "profile ") {
				cur = strings.TrimSpace(cur[len("profile "):])
			}
			continue
		}
		if cur == "" {
			continue
		}
		if idx := strings.Index(l2, "="); idx >= 0 {
			key := strings.TrimSpace(l2[:idx])
			val := strings.TrimSpace(l2[idx+1:])
			if key == "mfa_serial" && val != "" {
				curHasMfa = true
			}
		}
	}
	if cur != "" && curHasMfa {
		out = append(out, cur)
	}
	return out, nil
}

func writeCredentialsSection(section string, kv map[string]string) error {
	path := credentialsPath()
	// read existing
	data := ""
	if b, err := os.ReadFile(path); err == nil {
		data = string(b)
	}
	lines := strings.Split(data, "\n")
	var out []string
	in := false
	seen := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if in {
				// end of section
				// write our kv
				for k, v := range kv {
					out = append(out, fmt.Sprintf("%s = %s", k, v))
				}
				in = false
				seen = true
			}
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				// begin replace: skip the section header (we'll re-add)
				out = append(out, "["+section+"]")
				in = true
				// skip following lines until next section
				continue
			}
		}
		if in {
			// skip lines in old section
			// detect if next header coming handled above
			// simply continue
			continue
		}
		out = append(out, l)
	}
	if in && !seen {
		// write kv at end
		for k, v := range kv {
			out = append(out, fmt.Sprintf("%s = %s", k, v))
		}
		seen = true
	}
	if !seen {
		// append section
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, "["+section+"]")
		for k, v := range kv {
			out = append(out, fmt.Sprintf("%s = %s", k, v))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

func writeConfigSection(section string, kv map[string]string) error {
	path := configPath()
	data := ""
	if b, err := os.ReadFile(path); err == nil {
		data = string(b)
	}
	lines := strings.Split(data, "\n")
	var out []string
	in := false
	seen := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if in {
				for k, v := range kv {
					out = append(out, fmt.Sprintf("%s = %s", k, v))
				}
				in = false
				seen = true
			}
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				out = append(out, "["+section+"]")
				in = true
				continue
			}
		}
		if in {
			continue
		}
		out = append(out, l)
	}
	if in && !seen {
		for k, v := range kv {
			out = append(out, fmt.Sprintf("%s = %s", k, v))
		}
		seen = true
	}
	if !seen {
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, "["+section+"]")
		for k, v := range kv {
			out = append(out, fmt.Sprintf("%s = %s", k, v))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

// readConfigSection returns key/value map for a config section (e.g. "profile name"), or empty map if not found
func readConfigSection(section string) (map[string]string, error) {
	path := configPath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	in := false
	result := map[string]string{}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				in = true
				continue
			}
			if in {
				break
			}
		}
		if !in || t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if idx := strings.Index(t, "="); idx >= 0 {
			key := strings.TrimSpace(t[:idx])
			val := strings.TrimSpace(t[idx+1:])
			result[key] = val
		}
	}
	return result, nil
}

// deleteConfigSection removes a section from config file if present
func deleteConfigSection(section string) error {
	path := configPath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	in := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				in = true
				// skip header line
				continue
			}
			if in {
				in = false
			}
		}
		if in {
			continue
		}
		out = append(out, l)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

// readCredentialsSection returns key/value map for a credentials section, or empty map if not found
func readCredentialsSection(section string) (map[string]string, error) {
	path := credentialsPath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	in := false
	result := map[string]string{}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				in = true
				continue
			}
			if in {
				break
			}
		}
		if !in || t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if idx := strings.Index(t, "="); idx >= 0 {
			key := strings.TrimSpace(t[:idx])
			val := strings.TrimSpace(t[idx+1:])
			result[key] = val
		}
	}
	return result, nil
}

// deleteCredentialsSection removes a section from credentials file if present
func deleteCredentialsSection(section string) error {
	path := credentialsPath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	in := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur := strings.TrimSpace(t[1 : len(t)-1])
			if cur == section {
				in = true
				// skip header line
				continue
			}
			if in {
				in = false
			}
		}
		if in {
			continue
		}
		out = append(out, l)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}
