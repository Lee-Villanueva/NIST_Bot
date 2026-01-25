package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Lee-Villanueva/nist"
	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file, using system environment variables")
	}

	// Get bot token from environment variable
	token := os.Getenv("DISCORD_BOT_TOKEN")
	if token == "" {
		log.Fatal("DISCORD_BOT_TOKEN environment variable is not set")
	}

	// Create a new Discord session
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatal("Error creating Discord session:", err)
	}

	// Register handlers
	dg.AddHandler(messageCreate)
	dg.AddHandler(interactionCreate)

	// Set intents - MESSAGE CONTENT INTENT must be enabled in Discord Developer Portal
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentMessageContent

	// Open connection to Discord
	err = dg.Open()
	if err != nil {
		log.Fatal("Error opening connection:", err)
	}
	defer dg.Close()

	// Register slash commands
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "cve",
			Description: "Fetch CVE information from NIST database",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "cve-id",
					Description: "The CVE ID (e.g., CVE-2019-1010218)",
					Required:    true,
				},
			},
		},
	}

	fmt.Println("Registering slash commands...")
	registeredCommands := make([]*discordgo.ApplicationCommand, len(commands))
	for i, cmd := range commands {
		registeredCmd, err := dg.ApplicationCommandCreate(dg.State.User.ID, "", cmd)
		if err != nil {
			log.Printf("Cannot create '%v' command: %v", cmd.Name, err)
		} else {
			registeredCommands[i] = registeredCmd
			fmt.Printf("Registered command: %s\n", cmd.Name)
		}
	}

	// Set bot status
	err = dg.UpdateGameStatus(0, "/cve CVE-XXXX-XXXXX")
	if err != nil {
		log.Println("Error setting status:", err)
	}

	fmt.Println("Bot is now running. Press CTRL-C to exit.")
	fmt.Println("Use: /cve cve-id:CVE-XXXX-XXXXX")
	fmt.Println("Or: !cve CVE-XXXX-XXXXX")

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

func interactionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}

	// Get the CVE ID from the command options
	options := i.ApplicationCommandData().Options
	if len(options) == 0 {
		respondToInteraction(s, i, "Error: No CVE ID provided")
		return
	}

	cveID := strings.ToUpper(options[0].StringValue())

	// Defer the response to show "thinking" state
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})
	if err != nil {
		log.Println("Error deferring interaction:", err)
		return
	}

	// Fetch CVE data
	cveData, err := nist.FetchCVE(cveID)
	if err != nil {
		followupMessage(s, i, fmt.Sprintf("Error fetching CVE data: %v", err))
		return
	}

	// Check if CVE was found
	if len(cveData.Vulnerabilities) == 0 {
		followupMessage(s, i, fmt.Sprintf("No data found for %s", cveID))
		return
	}

	// Build response message
	response := buildCVEResponse(cveData)

	// Send follow-up message
	followupMessage(s, i, response)
}

func respondToInteraction(s *discordgo.Session, i *discordgo.InteractionCreate, content string) {
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: content,
		},
	})
}

func followupMessage(s *discordgo.Session, i *discordgo.InteractionCreate, content string) {
	// Split message if it's too long (Discord limit is 2000 characters)
	if len(content) > 2000 {
		content = content[:1997] + "..."
	}

	_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
		Content: content,
	})
	if err != nil {
		log.Println("Error sending follow-up message:", err)
	}
}

func buildCVEResponse(cveData *nist.CVE) string {
	cve := cveData.Vulnerabilities[0].CVE
	response := fmt.Sprintf("**%s**\n", cve.ID)
	response += fmt.Sprintf("Status: %s\n", cve.VulnStatus)
	response += fmt.Sprintf("Published: %s\n", cve.Published)
	response += fmt.Sprintf("Last Modified: %s\n\n", cve.LastModified)

	// Add description
	if len(cve.Descriptions) > 0 {
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				response += fmt.Sprintf("**Description:**\n%s\n\n", desc.Value)
				break
			}
		}
	}

	// Add CVSS score if available
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		cvss := cve.Metrics.CVSSMetricV31[0].CVSSData
		response += fmt.Sprintf("**CVSS v3.1 Score:** %.1f (%s)\n", cvss.BaseScore, cvss.BaseSeverity)
		response += fmt.Sprintf("Vector: %s\n", cvss.VectorString)
	}

	return response
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore bot's own messages
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Check if message starts with !cve
	if !strings.HasPrefix(m.Content, "!cve ") {
		return
	}

	// Extract CVE ID
	parts := strings.Fields(m.Content)
	if len(parts) < 2 {
		s.ChannelMessageSend(m.ChannelID, "Usage: !cve CVE-XXXX-XXXXX")
		return
	}

	cveID := strings.ToUpper(parts[1])

	// Send typing indicator
	s.ChannelTyping(m.ChannelID)

	// Fetch CVE data
	cveData, err := nist.FetchCVE(cveID)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Error fetching CVE data: %v", err))
		return
	}

	// Check if CVE was found
	if len(cveData.Vulnerabilities) == 0 {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("No data found for %s", cveID))
		return
	}

	// Build and send response message
	response := buildCVEResponse(cveData)

	// Split message if it's too long (Discord limit is 2000 characters)
	if len(response) > 2000 {
		response = response[:1997] + "..."
	}

	s.ChannelMessageSend(m.ChannelID, response)
}
