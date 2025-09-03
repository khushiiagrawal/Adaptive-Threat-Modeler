#!/bin/bash

# Setup Git Hooks for Commit Analysis
# This script sets up git hooks to automatically analyze commit differences

set -e

echo "🔧 Setting up Git Hooks for Commit Analysis..."

# Find the git repository root
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")
HOOKS_DIR="$REPO_ROOT/.git/hooks"
BACKEND_DIR="$REPO_ROOT/backend"

# Check if we're in a git repository
if [ ! -d "$HOOKS_DIR" ]; then
    echo "❌ Error: Not in a git repository or .git/hooks directory not found"
    exit 1
fi

# Check if backend directory exists
if [ ! -d "$BACKEND_DIR" ]; then
    echo "❌ Error: Backend directory not found at $BACKEND_DIR"
    exit 1
fi

echo "📁 Repository root: $REPO_ROOT"
echo "📁 Hooks directory: $HOOKS_DIR"
echo "📁 Backend directory: $BACKEND_DIR"

# Create post-commit hook
POST_COMMIT_HOOK="$HOOKS_DIR/post-commit"

cat > "$POST_COMMIT_HOOK" << 'EOF'
#!/bin/bash

# Post-commit hook to analyze commit differences
# This hook runs after a commit is successfully made

echo "🎯 Post-commit hook: Analyzing commit differences..."

# Get the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)
BACKEND_DIR="$REPO_ROOT/backend"

# Check if the git-hook binary exists, if not build it
GIT_HOOK_BINARY="$BACKEND_DIR/bin/git-hook"

if [ ! -f "$GIT_HOOK_BINARY" ]; then
    echo "🔨 Building git-hook binary..."
    cd "$BACKEND_DIR"
    mkdir -p bin
    go build -o bin/git-hook ./cmd/git-hook/main.go
    if [ $? -ne 0 ]; then
        echo "❌ Failed to build git-hook binary"
        exit 1
    fi
    echo "✅ Git-hook binary built successfully"
fi

# Run the commit analysis
echo "🔍 Running commit analysis..."
cd "$REPO_ROOT"
"$GIT_HOOK_BINARY" --hook --api --api-url "http://localhost:8000" --repo "$REPO_ROOT"

echo "✅ Post-commit analysis complete!"
EOF

# Make the hook executable
chmod +x "$POST_COMMIT_HOOK"

# Create prepare-commit-msg hook (optional - runs before commit)
PREPARE_COMMIT_HOOK="$HOOKS_DIR/prepare-commit-msg"

cat > "$PREPARE_COMMIT_HOOK" << 'EOF'
#!/bin/bash

# Prepare-commit-msg hook
# This hook runs before the commit message is finalized
# It can be used to add commit analysis information to the commit message

COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2
SHA1=$3

# Only run for regular commits (not merges, etc.)
if [ "$COMMIT_SOURCE" = "" ]; then
    echo "" >> "$COMMIT_MSG_FILE"
    echo "# Commit will be analyzed post-commit for security and code changes" >> "$COMMIT_MSG_FILE"
fi
EOF

chmod +x "$PREPARE_COMMIT_HOOK"

# Build the git-hook binary
echo "🔨 Building git-hook binary..."
cd "$BACKEND_DIR"
mkdir -p bin
go build -o bin/git-hook ./cmd/git-hook/main.go

if [ $? -eq 0 ]; then
    echo "✅ Git-hook binary built successfully"
else
    echo "❌ Failed to build git-hook binary"
    exit 1
fi

echo ""
echo "✅ Git hooks setup complete!"
echo ""
echo "📋 What was set up:"
echo "   • Post-commit hook: $POST_COMMIT_HOOK"
echo "   • Prepare-commit-msg hook: $PREPARE_COMMIT_HOOK"
echo "   • Git-hook binary: $BACKEND_DIR/bin/git-hook"
echo ""
echo "🎯 How it works:"
echo "   • Every time you make a commit, the post-commit hook will run"
echo "   • It will analyze the commit differences and print them to console"
echo "   • A log file will be created at .git/commit-analysis.log"
echo ""
echo "🧪 Test it:"
echo "   • Make a test commit: git commit -m 'Test commit analysis'"
echo "   • Or run manually: $BACKEND_DIR/bin/git-hook"
echo "   • Or analyze specific commit: $BACKEND_DIR/bin/git-hook --commit <hash>"
echo ""
echo "🗑️ To remove hooks:"
echo "   • Delete: $POST_COMMIT_HOOK"
echo "   • Delete: $PREPARE_COMMIT_HOOK"
