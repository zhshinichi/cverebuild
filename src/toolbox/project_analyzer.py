"""
项目结构分析工具

在构建项目之前分析目录结构，识别主语言和构建系统，
避免使用错误的工具（如用 pip 构建 Go 项目）。
"""

import os
from collections import Counter
from agentlib.lib import tools


# Language extensions mapping
LANGUAGE_EXTENSIONS = {
    '.go': 'Go',
    '.py': 'Python',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.jsx': 'React JSX',
    '.tsx': 'React TSX',
    '.java': 'Java',
    '.kt': 'Kotlin',
    '.cs': 'C#',
    '.fs': 'F#',
    '.vb': 'Visual Basic',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.rs': 'Rust',
    '.c': 'C',
    '.cpp': 'C++',
    '.h': 'C/C++ Header',
    '.swift': 'Swift',
    '.scala': 'Scala',
    '.pl': 'Perl',
    '.lua': 'Lua',
    '.ex': 'Elixir',
    '.erl': 'Erlang',
}

# Build system files mapping
BUILD_SYSTEM_FILES = {
    'go.mod': ('Go Modules', 'go mod tidy && go build ./...'),
    'go.sum': ('Go Modules', 'go mod tidy && go build ./...'),
    'package.json': ('npm/Node.js', 'npm install'),
    'yarn.lock': ('Yarn', 'yarn install'),
    'pnpm-lock.yaml': ('pnpm', 'pnpm install'),
    'pom.xml': ('Maven', 'mvn clean install -DskipTests'),
    'build.gradle': ('Gradle', './gradlew build'),
    'build.gradle.kts': ('Gradle (Kotlin DSL)', './gradlew build'),
    'Makefile': ('Make', 'make'),
    'CMakeLists.txt': ('CMake', 'mkdir build && cd build && cmake .. && make'),
    'setup.py': ('Python setuptools', 'pip install -e .'),
    'pyproject.toml': ('Python (modern)', 'pip install -e .'),
    'requirements.txt': ('Python pip', 'pip install -r requirements.txt'),
    'Pipfile': ('Pipenv', 'pipenv install'),
    'poetry.lock': ('Poetry', 'poetry install'),
    'Cargo.toml': ('Rust Cargo', 'cargo build'),
    'Gemfile': ('Ruby Bundler', 'bundle install'),
    'composer.json': ('PHP Composer', 'composer install'),
    'Dockerfile': ('Docker', 'docker build -t app .'),
    'docker-compose.yml': ('Docker Compose', 'docker-compose up -d'),
    'docker-compose.yaml': ('Docker Compose', 'docker-compose up -d'),
}

# Directories to skip when analyzing
SKIP_DIRECTORIES = {
    'node_modules', 'vendor', 'venv', '.venv', '__pycache__',
    'target', 'build', 'dist', '.git', '.idea', '.vscode',
    'agentlib', 'toolbox', 'agents', 'prompts', 'orchestrator', 'planner',
}


def _get_working_directory():
    """获取工作目录"""
    try:
        from toolbox.command_ops import get_working_directory
        return get_working_directory()
    except ImportError:
        return os.getcwd()


@tools.tool
def analyze_project_structure(directory: str = ".") -> str:
    """
    Analyze a project directory to identify its primary language, build system, and structure.
    
    🚨 MANDATORY: Run this tool BEFORE attempting any build commands!
    This helps avoid common mistakes like using pip for a Go project.
    
    :param directory: The directory to analyze (defaults to current working directory)
    :return: A detailed report of the project structure
    """
    # Resolve the directory path
    work_dir = _get_working_directory() if directory == "." else directory
    if not os.path.isdir(work_dir):
        return f"❌ Directory not found: {work_dir}"
    
    # Count file extensions
    extension_counts = Counter()
    total_files = 0
    build_systems_found = []
    special_files = []
    
    # Walk through the directory
    for root, dirs, files in os.walk(work_dir):
        # Skip hidden and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRECTORIES]
        
        # Limit depth to avoid very deep trees
        depth = root[len(work_dir):].count(os.sep)
        if depth > 5:
            continue
        
        for file in files:
            total_files += 1
            ext = os.path.splitext(file)[1].lower()
            if ext in LANGUAGE_EXTENSIONS:
                extension_counts[LANGUAGE_EXTENSIONS[ext]] += 1
            
            # Check for build system files
            if file in BUILD_SYSTEM_FILES:
                build_system, build_cmd = BUILD_SYSTEM_FILES[file]
                if (build_system, build_cmd) not in build_systems_found:
                    build_systems_found.append((build_system, build_cmd))
            
            # Check for .csproj and .sln files
            if file.endswith('.csproj'):
                build_systems_found.append(('MSBuild/.NET', f'dotnet restore && dotnet build {file}'))
                special_files.append(('C# Project', file))
            elif file.endswith('.sln'):
                build_systems_found.append(('.NET Solution', f'dotnet restore {file} && dotnet build {file}'))
                special_files.append(('.NET Solution', file))
    
    # Determine primary language
    if extension_counts:
        primary_lang = extension_counts.most_common(1)[0][0]
        lang_distribution = extension_counts.most_common(5)
    else:
        primary_lang = "Unknown"
        lang_distribution = []
    
    # Generate report
    report = []
    report.append("=" * 60)
    report.append("📊 PROJECT STRUCTURE ANALYSIS REPORT")
    report.append("=" * 60)
    report.append(f"\n📁 Directory: {work_dir}")
    report.append(f"📄 Total source files analyzed: {total_files}")
    
    report.append(f"\n🎯 PRIMARY LANGUAGE: {primary_lang}")
    
    if lang_distribution:
        report.append("\n📈 Language Distribution:")
        for lang, count in lang_distribution:
            percentage = (count / sum(extension_counts.values())) * 100
            bar = "█" * int(percentage / 5) + "░" * (20 - int(percentage / 5))
            report.append(f"   {lang:15} {bar} {percentage:5.1f}% ({count} files)")
    
    if build_systems_found:
        report.append("\n🔧 BUILD SYSTEMS DETECTED:")
        seen = set()
        for build_system, build_cmd in build_systems_found:
            if build_system not in seen:
                seen.add(build_system)
                report.append(f"   ✅ {build_system}")
                report.append(f"      Command: {build_cmd}")
    else:
        report.append("\n⚠️ No build system detected!")
    
    if special_files:
        report.append("\n📋 SPECIAL FILES FOUND:")
        for file_type, file_name in special_files[:5]:
            report.append(f"   • {file_type}: {file_name}")
    
    # Add recommendations based on primary language
    report.append("\n" + "=" * 60)
    report.append("💡 RECOMMENDED BUILD STRATEGY:")
    report.append("=" * 60)
    
    if primary_lang == "Go":
        report.append("""   For Go projects:
   1. Check go.mod for module name and dependencies
   2. Run: go mod tidy
   3. Run: go build ./... (or specific package)
   ❌ Do NOT use: pip, npm, dotnet""")
    elif primary_lang in ["Python"]:
        report.append("""   For Python projects:
   1. Create virtual environment if needed
   2. Install dependencies: pip install -r requirements.txt
   3. For libraries: pip install -e .
   ❌ Do NOT use: go build, npm, dotnet""")
    elif primary_lang in ["JavaScript", "TypeScript", "React JSX", "React TSX"]:
        report.append("""   For Node.js projects:
   1. Install dependencies: npm install (or yarn/pnpm)
   2. Build if needed: npm run build
   3. Start: npm start (or npm run dev)
   ❌ Do NOT use: pip, go build, dotnet""")
    elif primary_lang in ["C#", "F#", "Visual Basic"]:
        report.append("""   For .NET projects:
   1. Restore packages: dotnet restore
   2. Build: dotnet build
   3. Run tests: dotnet test
   ❌ Do NOT use: pip, npm, go build""")
    elif primary_lang == "Java" or primary_lang == "Kotlin":
        report.append("""   For Java/Kotlin projects:
   1. Maven: mvn clean install -DskipTests
   2. Gradle: ./gradlew build
   ❌ Do NOT use: pip, npm, go build""")
    elif primary_lang == "Rust":
        report.append("""   For Rust projects:
   1. Build: cargo build
   2. Run: cargo run
   ❌ Do NOT use: pip, npm, go build""")
    else:
        report.append(f"   No specific recommendation for {primary_lang}")
    
    report.append("\n" + "=" * 60)
    
    return "\n".join(report)


# 导出工具供 TOOLS 字典使用
PROJECT_ANALYZER_TOOLS = {
    "analyze_project_structure": analyze_project_structure,
}
