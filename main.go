package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var accessToken string

func main() {
	r := gin.Default()

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	clientID := os.Getenv("clientID")
	clientSecret := os.Getenv("clientSecret")
	redirectURI := os.Getenv("redirectURI")

	// Validate environment variables
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		log.Fatalf("Missing required environment variables: clientID, clientSecret, or redirectURI")
	}

	// Step 1: Redirect to GitHub for Authentication
	r.GET("/login/oauth", func(c *gin.Context) {
		println("clientID", os.Getenv("clientID"))
		authURL := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=repo",
			os.Getenv("clientID"), os.Getenv("redirectURI"),
		)
		c.Redirect(http.StatusFound, authURL)
	})

	// Step 2: Handle GitHub Callback and Exchange Code for Access Token
	r.GET("/oauth-callback", func(c *gin.Context) {
		code := c.Query("code")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
			return
		}

		token, err := getAccessToken(code)
		if err != nil {
			log.Println("Error getting access token:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get access token"})
			return
		}

		accessToken = token
		log.Println("Access Token:", accessToken) // Log the token
		c.JSON(http.StatusOK, gin.H{"message": "Authentication successful!"})
	})

	r.GET("/repos/:owner/:repo/tree-content", func(c *gin.Context) {
		owner := c.Param("owner")
		repo := c.Param("repo")
		branch := c.Query("branch")
		if branch == "" {
			branch = "main" // Default to main branch
		}

		tree, err := fetchTreeWithFilteredContent(owner, repo, branch)
		if err != nil {
			log.Printf("Error fetching repository tree: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch repository tree"})
			return
		}

		c.JSON(http.StatusOK, tree)
	})

	r.Run(":3000")
}

// Function to Exchange Code for Access Token
func getAccessToken(code string) (string, error) {
	tokenURL := "https://github.com/login/oauth/access_token"
	data := url.Values{}
	data.Set("client_id", os.Getenv("clientID"))
	data.Set("client_secret", os.Getenv("clientSecret"))
	data.Set("code", code)
	data.Set("redirect_uri", os.Getenv("redirectURI"))

	req, err := http.NewRequest("POST", tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = data.Encode()
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access token found in response")
	}

	return token, nil
}

// fetchTreeWithFilteredContent fetches the repository tree, filters code files, and retrieves their content.
func fetchTreeWithFilteredContent(owner, repo, branch string) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)

	// Fetch the repository tree
	treeResponse, err := makeGitHubAPIRequest(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository tree: %w", err)
	}

	// Parse the tree data
	var treeData map[string]interface{}
	if err := json.Unmarshal(treeResponse, &treeData); err != nil {
		return nil, fmt.Errorf("failed to parse tree data: %w", err)
	}

	// Filter for code files
	codeFiles := filterCodeFiles(treeData["tree"].([]interface{}))

	// Fetch content concurrently for each file
	filesWithContent, err := fetchFileContentsConcurrently(owner, repo, codeFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file contents: %w", err)
	}

	return map[string]interface{}{
		"sha":   treeData["sha"],
		"files": filesWithContent,
	}, nil
}

// fetchFileContentsConcurrently fetches file content concurrently using Goroutines
func fetchFileContentsConcurrently(owner, repo string, files []map[string]interface{}) ([]map[string]interface{}, error) {
	var result []map[string]interface{}
	var mu sync.Mutex // To protect shared data
	var wg sync.WaitGroup
	errChan := make(chan error, len(files)) // Channel to capture errors

	for _, file := range files {
		wg.Add(1)

		go func(file map[string]interface{}) {
			defer wg.Done()

			filePath := file["path"].(string)
			blobSHA := file["sha"].(string)

			content, err := fetchFileContent(owner, repo, blobSHA)
			if err != nil {
				errChan <- fmt.Errorf("failed to fetch content for file '%s': %w", filePath, err)
				return
			}

			mu.Lock()
			result = append(result, map[string]interface{}{
				"path":    filePath,
				"content": content,
			})
			mu.Unlock()
		}(file)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan // Return the first error
	}

	return result, nil
}

// fetchFileContent fetches the content of a file blob
func fetchFileContent(owner, repo, blobSHA string) (string, error) {
	blobURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/blobs/%s", owner, repo, blobSHA)

	blobResponse, err := makeGitHubAPIRequest(blobURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch blob content: %w", err)
	}

	var blobData map[string]interface{}
	if err := json.Unmarshal(blobResponse, &blobData); err != nil {
		return "", fmt.Errorf("failed to parse blob data: %w", err)
	}

	encodedContent := blobData["content"].(string)
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedContent))
	if err != nil {
		return "", fmt.Errorf("failed to decode blob content: %w", err)
	}

	return string(content), nil
}

// filterCodeFiles filters the tree data for code files based on file extensions
func filterCodeFiles(tree []interface{}) []map[string]interface{} {
	codeExtensions := map[string]bool{
		".go":   true,
		".js":   true,
		".py":   true,
		".ts":   true,
		".java": true,
		".c":    true,
		".cpp":  true,
		".rb":   true,
	}

	var filtered []map[string]interface{}
	for _, node := range tree {
		nodeMap := node.(map[string]interface{})
		path := nodeMap["path"].(string)

		if ext := filepath.Ext(path); codeExtensions[ext] {
			filtered = append(filtered, nodeMap)
		}
	}
	return filtered
}

// makeGitHubAPIRequest makes a generic API request to GitHub
func makeGitHubAPIRequest(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API call failed: %s (%d)", url, resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}
