# Enter your GitHub personal access token (with delete_repo permission)
$accessToken = "<your_access_token>"

# Path to the text file containing the list of repositories to delete
$repoListPath = "<path_to_repo_list.txt>"

# Read the list of repositories from the file
$reposToDelete = Get-Content $repoListPath

# Confirmation prompt before deletion
if (-not (Confirm-Question "This script will attempt to delete repositories from your GitHub account. Are you sure you want to continue?")) {
  Exit-Host
}

# Loop through each repository in the list
foreach ($repo in $reposToDelete) {
  # Extract username and repository name
  $parts = $repo.Split("/")
  $username = $parts[0]
  $repoName = $parts[1]

  # Construct the API URL for the repository
  $url = "https://api.github.com/repos/$username/$repoName"

  # Set authorization header with your personal access token
  $headers = @{
    "Authorization" = "Bearer $accessToken"
    "Accept" = "application/vnd.github+json"
  }

  try {
    # Send DELETE request to delete the repository
    Invoke-RestMethod -Uri $url -Method Delete -Headers $headers
    Write-Host "Successfully deleted repository: $repo"
  } catch {
    # Handle errors during deletion
    Write-Error "Error deleting repository: $repo ($_.Exception.Message)"
  }
}

Write-Host "Script execution complete."
