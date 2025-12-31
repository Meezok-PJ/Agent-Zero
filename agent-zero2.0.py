#!/usr/bin/env python3
"""
Agent-Zero 2.0: Interactive Terminal UI Version
================================================

An interactive menu-driven version of Agent-Zero with persistent configuration,
enhanced shell support, and user-friendly terminal interface.

Features:
- Interactive menu system with prompt_toolkit
- Persistent configuration storage
- Enhanced zshrc/bashrc support
- All analysis features from Agent-Zero.py
- User-friendly error handling and progress indicators

Usage:
  python agent-zero2.0.py
"""

import os
import sys
import json
import subprocess
import platform
import shutil
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Import the analyzer from Agent-Zero.py
try:
    # Import EnhancedBinaryAnalyzer from Agent-Zero.py using importlib due to hyphen in filename
    import importlib.util
    agent_zero_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Agent-Zero.py")
    if not os.path.exists(agent_zero_path):
        raise FileNotFoundError(f"Agent-Zero.py not found at {agent_zero_path}")
    
    spec = importlib.util.spec_from_file_location("agent_zero_module", agent_zero_path)
    agent_zero_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent_zero_module)
    EnhancedBinaryAnalyzer = agent_zero_module.EnhancedBinaryAnalyzer
except (ImportError, FileNotFoundError, AttributeError) as e:
    print(f"Error: Could not import EnhancedBinaryAnalyzer from Agent-Zero.py: {e}")
    print("Please ensure Agent-Zero.py is in the same directory.")
    sys.exit(1)

# Try to import prompt_toolkit
try:
    from prompt_toolkit import prompt, print_formatted_text
    from prompt_toolkit.shortcuts import yes_no_dialog, button_dialog, radiolist_dialog
    from prompt_toolkit.completion import PathCompleter, WordCompleter
    from prompt_toolkit.formatted_text import HTML, ANSI
    from prompt_toolkit.validation import Validator, ValidationError
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    print("Error: prompt_toolkit is not installed.")
    print("Please install it with: pip install prompt_toolkit")
    sys.exit(1)

# Rich library for enhanced output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich.markdown import Markdown
    from rich import box
    console = Console()
except ImportError:
    console = None

# Requests for Ollama API
try:
    import requests
except ImportError:
    print("Error: requests library is not installed.")
    print("Please install it with: pip install requests")
    sys.exit(1)

# ==================== CONFIGURATION MANAGEMENT ====================

class InteractiveConfig:
    """Manages persistent configuration for Agent-Zero 2.0."""
    
    CONFIG_PATH = Path.home() / ".agent-zero-config.json"
    
    DEFAULTS = {
        "model": "llama3.2",
        "ollama_url": "http://localhost:11434",
        "no_floss": False,
        "no_capa": False,
        "no_vt": False,
        "no_dynamic": False,
        "capa_verbose": False,
        "no_llm": False,
        "vt_api_key": "",
        "hybrid_analysis_api_key": "",
        "output_dir": "./output",
        "retries": 3,
        "shell_type": None,  # Auto-detect
        "shell_rc_file": None,  # Auto-detect
        "custom_capa_path": "",
        "custom_floss_path": ""
    }
    
    def __init__(self):
        """Initialize configuration, loading from file or using defaults."""
        self.config = self.DEFAULTS.copy()
        # Override with environment variables if set
        if os.environ.get('OLLAMA_URL'):
            self.config['ollama_url'] = os.environ.get('OLLAMA_URL')
        self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        if self.CONFIG_PATH.exists():
            try:
                with open(self.CONFIG_PATH, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to handle new keys
                    self.config = {**self.DEFAULTS, **loaded_config}
                    if console:
                        console.print(f"[green]✓ Configuration loaded from {self.CONFIG_PATH}[/green]")
            except Exception as e:
                if console:
                    console.print(f"[yellow]Warning: Failed to load config: {e}[/yellow]")
                    console.print("[cyan]Using default configuration[/cyan]")
                self.config = self.DEFAULTS.copy()
        else:
            # Create config file with defaults on first run
            self.save_config()
        # Override with environment variables if set (environment takes precedence)
        if os.environ.get('OLLAMA_URL'):
            self.config['ollama_url'] = os.environ.get('OLLAMA_URL')
        return self.config
    
    def save_config(self) -> bool:
        """Save configuration to JSON file."""
        try:
            # Ensure directory exists
            self.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            
            if console:
                console.print(f"[green]✓ Configuration saved to {self.CONFIG_PATH}[/green]")
            return True
        except Exception as e:
            if console:
                console.print(f"[red]Error saving configuration: {e}[/red]")
            return False
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        return self.config.get(key, default if default is not None else self.DEFAULTS.get(key))
    
    def set_setting(self, key: str, value: Any) -> bool:
        """Update a setting value."""
        if key in self.DEFAULTS:
            self.config[key] = value
            return self.save_config()
        else:
            if console:
                console.print(f"[yellow]Warning: Unknown setting key: {key}[/yellow]")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset all settings to defaults."""
        self.config = self.DEFAULTS.copy()
        return self.save_config()
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all current settings (for display)."""
        return self.config.copy()
    
    def to_args_namespace(self):
        """Convert config to argparse.Namespace-like object for analyzer."""
        class Args:
            def __init__(self, config_dict):
                for key, value in config_dict.items():
                    setattr(self, key, value)
        
        # Map config keys to expected analyzer attribute names
        # Fix Ollama URL to include /api/generate endpoint
        ollama_url = self.config.get('ollama_url', 'http://localhost:11434')
        # Append /api/generate if not present
        if not ollama_url.endswith('/api/generate'):
            if ollama_url.endswith('/'):
                ollama_url = ollama_url + 'api/generate'
            else:
                ollama_url = ollama_url + '/api/generate'
        
        args_dict = {
            'file': None,  # Will be set when running analysis
            'model': self.config.get('model', 'llama3.2'),
            'ollama_url': ollama_url,
            'outdir': self.config.get('output_dir', './output'),
            'retries': self.config.get('retries', 3),
            'no_floss': self.config.get('no_floss', False),
            'no_capa': self.config.get('no_capa', False),
            'no_vt': self.config.get('no_vt', False),
            'no_dynamic': self.config.get('no_dynamic', False),
            'capa_verbose': self.config.get('capa_verbose', False),
            'no_llm': self.config.get('no_llm', False),
            'vt_only': False,
            'dataset_csv': None,
            'stage_reports': True,
            '_web_mode': False
        }
        return Args(args_dict)

# ==================== ENHANCED SHELL DETECTION ====================

def detect_shell_config() -> Tuple[Optional[str], Optional[Path]]:
    """Enhanced shell detection with better error handling.
    
    Returns:
        Tuple of (shell_name, rc_file_path) or (None, None) if not found
    """
    shell = os.environ.get('SHELL', '')
    home = Path.home()
    
    # Priority order: zsh, bash
    # Check zsh first
    zshrc_path = home / '.zshrc'
    if ('zsh' in shell.lower()) or zshrc_path.exists():
        if zshrc_path.exists():
            return 'zsh', zshrc_path
        elif shutil.which('zsh'):
            # zsh is available but .zshrc doesn't exist
            return 'zsh', None
    
    # Check bash
    bashrc_path = home / '.bashrc'
    bash_profile_path = home / '.bash_profile'
    
    if ('bash' in shell.lower()) or bashrc_path.exists() or bash_profile_path.exists():
        if bashrc_path.exists():
            return 'bash', bashrc_path
        elif bash_profile_path.exists():
            return 'bash', bash_profile_path
        elif shutil.which('bash'):
            return 'bash', None
    
    # Fallback: try to detect from SHELL env var
    if shell:
        if 'zsh' in shell.lower():
            return 'zsh', zshrc_path if zshrc_path.exists() else None
        elif 'bash' in shell.lower():
            return 'bash', bashrc_path if bashrc_path.exists() else None
    
    return None, None

def test_shell_tool(shell_name: str, rc_file: Optional[Path], tool_name: str) -> Tuple[bool, str]:
    """Test if a tool is available via shell alias or PATH.
    
    Returns:
        Tuple of (is_available, diagnostic_message)
    """
    if not shell_name:
        # Try PATH-based lookup
        tool_path = shutil.which(tool_name)
        if tool_path:
            return True, f"Found in PATH: {tool_path}"
        return False, f"Tool '{tool_name}' not found in PATH"
    
    # Try shell execution
    shell_cmd = shutil.which(shell_name)
    if not shell_cmd:
        return False, f"Shell '{shell_name}' not found in PATH"
    
    # Test command
    test_cmd = f"type {tool_name}"
    if rc_file and rc_file.exists():
        shell_command_str = f"source '{rc_file}' 2>/dev/null; {test_cmd}"
    else:
        shell_command_str = test_cmd
    
    try:
        result = subprocess.run(
            [shell_cmd, '-i', '-c', shell_command_str],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            output = result.stdout.strip()
            if 'alias' in output.lower():
                return True, f"Found as alias: {output}"
            elif tool_name in output:
                return True, f"Found in shell: {output}"
        
        # Try PATH as fallback
        tool_path = shutil.which(tool_name)
        if tool_path:
            return True, f"Found in PATH: {tool_path}"
        
        return False, f"Tool '{tool_name}' not found via shell or PATH"
    except Exception as e:
        return False, f"Error testing tool: {str(e)}"

# ==================== INTERACTIVE MENU SYSTEM ====================

class InteractiveAgentZero:
    """Interactive menu-driven interface for Agent-Zero."""
    
    def __init__(self):
        """Initialize the interactive interface."""
        self.config = InteractiveConfig()
        self.running = True
    
    def show_main_menu(self) -> str:
        """Display the main menu and get user choice."""
        menu_content = """[bold cyan]1.[/bold cyan] Select LLM Model
[bold cyan]2.[/bold cyan] Configure Analysis Options
[bold cyan]3.[/bold cyan] Set API Keys
[bold cyan]4.[/bold cyan] Run Analysis
[bold cyan]5.[/bold cyan] View Previous Reports
[bold cyan]6.[/bold cyan] Advanced Settings
[bold cyan]7.[/bold cyan] Show Current Configuration
[bold cyan]8.[/bold cyan] Test Tools (CAPA, FLOSS)
[bold cyan]9.[/bold cyan] Search theZoo Malware Repository
[bold cyan]10.[/bold cyan] Exit"""
        
        if console:
            menu_panel = Panel.fit(
                menu_content,
                title="[bold magenta]Agent-Zero 2.0 Interactive Mode[/bold magenta]",
                border_style="magenta",
                box=box.DOUBLE
            )
            console.print(menu_panel)
            console.print()
            # Display formatted prompt text using Rich
            console.print("[bold yellow]Enter option [1-10]:[/bold yellow] ", end="")
        else:
            print("Enter option [1-10]: ", end="")
        
        # Use plain prompt for input
        choice = prompt("", default="").strip()
        return choice
    
    def select_llm_model(self):
        """Interactive LLM model selection."""
        ollama_url = self.config.get_setting('ollama_url', 'http://localhost:11434')
        
        if console:
            console.print("[cyan]Fetching available models from Ollama...[/cyan]")
        
        try:
            # Query Ollama API for available models
            response = requests.get(f"{ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models_data = response.json()
                models = [model['name'] for model in models_data.get('models', [])]
                
                if not models:
                    console.print("[yellow]No models found. Please install a model first.[/yellow]")
                    console.print("[cyan]Example: ollama pull llama3.2[/cyan]")
                    prompt("\nPress Enter to continue...")
                    return
                
                # Show model selection dialog
                selected = radiolist_dialog(
                    title="Select LLM Model",
                    text="Choose a model for analysis:",
                    values=[(model, model) for model in models],
                    default=self.config.get_setting('model')
                ).run()
                
                if selected:
                    self.config.set_setting('model', selected)
                    console.print(f"[green]✓ Model set to: {selected}[/green]")
                else:
                    console.print("[yellow]No model selected[/yellow]")
            else:
                console.print(f"[red]Failed to connect to Ollama at {ollama_url}[/red]")
                console.print("[yellow]Make sure Ollama is running.[/yellow]")
                prompt("\nPress Enter to continue...")
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error connecting to Ollama: {e}[/red]")
            console.print(f"[yellow]Ollama URL: {ollama_url}[/yellow]")
            prompt("\nPress Enter to continue...")
    
    def configure_analysis_options(self):
        """Configure analysis options sub-menu."""
        options_content = f"""[bold cyan]1.[/bold cyan] Toggle FLOSS (Currently: [{'[red]Disabled[/red]' if self.config.get_setting('no_floss') else '[green]Enabled[/green]'}])
[bold cyan]2.[/bold cyan] Toggle CAPA (Currently: [{'[red]Disabled[/red]' if self.config.get_setting('no_capa') else '[green]Enabled[/green]'}])
[bold cyan]3.[/bold cyan] Toggle VirusTotal (Currently: [{'[red]Disabled[/red]' if self.config.get_setting('no_vt') else '[green]Enabled[/green]'}])
[bold cyan]4.[/bold cyan] Toggle Dynamic Analysis (Currently: [{'[red]Disabled[/red]' if self.config.get_setting('no_dynamic') else '[green]Enabled[/green]'}])
[bold cyan]5.[/bold cyan] Toggle CAPA Verbose Mode (Currently: [{'[green]Enabled[/green]' if self.config.get_setting('capa_verbose') else '[yellow]Disabled[/yellow]'}])
[bold cyan]6.[/bold cyan] Toggle LLM Analysis (Currently: [{'[red]Disabled[/red]' if self.config.get_setting('no_llm') else '[green]Enabled[/green]'}])
[bold cyan]7.[/bold cyan] Back to Main Menu"""
        
        if console:
            options_panel = Panel.fit(
                options_content,
                title="[bold cyan]Configure Analysis Options[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            )
            console.print(options_panel)
            console.print()
            # Display formatted prompt text using Rich
            console.print("[bold yellow]Enter option [1-7]:[/bold yellow] ", end="")
        else:
            print("Enter option [1-7]: ", end="")
        
        # Use plain prompt for input
        choice = prompt("", default="").strip()
        
        if choice == "1":
            current = self.config.get_setting('no_floss')
            self.config.set_setting('no_floss', not current)
            console.print(f"[green]✓ FLOSS {'disabled' if not current else 'enabled'}[/green]")
        elif choice == "2":
            current = self.config.get_setting('no_capa')
            self.config.set_setting('no_capa', not current)
            console.print(f"[green]✓ CAPA {'disabled' if not current else 'enabled'}[/green]")
        elif choice == "3":
            current = self.config.get_setting('no_vt')
            self.config.set_setting('no_vt', not current)
            console.print(f"[green]✓ VirusTotal {'disabled' if not current else 'enabled'}[/green]")
        elif choice == "4":
            current = self.config.get_setting('no_dynamic')
            self.config.set_setting('no_dynamic', not current)
            console.print(f"[green]✓ Dynamic Analysis {'disabled' if not current else 'enabled'}[/green]")
        elif choice == "5":
            current = self.config.get_setting('capa_verbose')
            self.config.set_setting('capa_verbose', not current)
            console.print(f"[green]✓ CAPA Verbose Mode {'enabled' if not current else 'disabled'}[/green]")
        elif choice == "6":
            current = self.config.get_setting('no_llm')
            self.config.set_setting('no_llm', not current)
            console.print(f"[green]✓ LLM Analysis {'disabled' if not current else 'enabled'}[/green]")
    
    def set_api_keys(self):
        """Set API keys menu."""
        if console:
            api_keys_panel = Panel.fit(
                "[yellow]Note: Keys are stored in configuration file[/yellow]",
                title="[bold green]API Keys Configuration[/bold green]",
                border_style="green",
                box=box.ROUNDED
            )
            console.print()
            console.print(api_keys_panel)
            console.print()
        
        # VirusTotal API Key
        current_vt = self.config.get_setting('vt_api_key', '')
        vt_key = prompt(f"VirusTotal API Key [{len(current_vt) if current_vt else 0} chars, leave empty to keep current]: ", default="").strip()
        if vt_key:
            self.config.set_setting('vt_api_key', vt_key)
            console.print("[green]✓ VirusTotal API key updated[/green]")
            # Set environment variable
            os.environ['VT_API_KEY'] = vt_key
        
        # Hybrid Analysis API Key
        current_ha = self.config.get_setting('hybrid_analysis_api_key', '')
        ha_key = prompt(f"Hybrid Analysis API Key [{len(current_ha) if current_ha else 0} chars, leave empty to keep current]: ", default="").strip()
        if ha_key:
            self.config.set_setting('hybrid_analysis_api_key', ha_key)
            console.print("[green]✓ Hybrid Analysis API key updated[/green]")
            # Set environment variable
            os.environ['HYBRID_ANALYSIS_API_KEY'] = ha_key
    
    def run_analysis_interactive(self):
        """Run analysis with interactive file selection."""
        # Get file path
        file_completer = PathCompleter(only_directories=False, expanduser=True)
        file_path = prompt("Enter path to binary file: ", completer=file_completer).strip()
        
        if not file_path or not os.path.exists(file_path):
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            prompt("\nPress Enter to continue...")
            return
        
        # Confirm settings
        console.print("\n[bold]Analysis Configuration:[/bold]")
        settings_table = Table(show_header=True, header_style="bold magenta")
        settings_table.add_column("Setting", style="cyan")
        settings_table.add_column("Value", style="yellow")
        
        settings_table.add_row("Model", self.config.get_setting('model'))
        settings_table.add_row("FLOSS", "Disabled" if self.config.get_setting('no_floss') else "Enabled")
        settings_table.add_row("CAPA", "Disabled" if self.config.get_setting('no_capa') else "Enabled")
        settings_table.add_row("VirusTotal", "Disabled" if self.config.get_setting('no_vt') else "Enabled")
        settings_table.add_row("Dynamic Analysis", "Disabled" if self.config.get_setting('no_dynamic') else "Enabled")
        
        console.print(settings_table)
        
        if not yes_no_dialog(
            title="Confirm Analysis",
            text="Run analysis with these settings?"
        ).run():
            console.print("[yellow]Analysis cancelled[/yellow]")
            return
        
        # Create args namespace
        args = self.config.to_args_namespace()
        args.file = file_path
        
        # Set API keys in environment
        if self.config.get_setting('vt_api_key'):
            os.environ['VT_API_KEY'] = self.config.get_setting('vt_api_key')
        if self.config.get_setting('hybrid_analysis_api_key'):
            os.environ['HYBRID_ANALYSIS_API_KEY'] = self.config.get_setting('hybrid_analysis_api_key')
        
        try:
            # Create analyzer and run
            analyzer = EnhancedBinaryAnalyzer(args)
            analyzer.run_analysis()
            
            console.print("\n[green]✓ Analysis completed![/green]")
            console.print(f"[cyan]Reports saved to: {args.outdir}[/cyan]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error during analysis: {e}[/red]")
            if console:
                import traceback
                console.print("[dim]" + traceback.format_exc() + "[/dim]")
        
        prompt("\nPress Enter to continue...")
    
    def view_reports(self):
        """View previous analysis reports."""
        output_dir = Path(self.config.get_setting('output_dir', './output'))
        
        if not output_dir.exists():
            console.print(f"[yellow]Output directory not found: {output_dir}[/yellow]")
            prompt("\nPress Enter to continue...")
            return
        
        json_reports = sorted(output_dir.glob("analysis_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
        display_reports = json_reports[:20]
        
        if not json_reports:
            console.print("[yellow]No JSON reports found yet[/yellow]")
            prompt("\nPress Enter to continue...")
            return
        
        table = Table(
            title="[bold magenta]Available Analysis Reports[/bold magenta]",
            header_style="bold cyan",
            box=box.ROUNDED
        )
        table.add_column("#", justify="right")
        table.add_column("Generated", style="green")
        table.add_column("JSON File", style="cyan")
        table.add_column("Size (KB)", justify="right")
        table.add_column("Markdown?", style="magenta")
        
        for idx, report in enumerate(display_reports, 1):
            md_file = report.with_suffix('.md')
            timestamp = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size_kb = f"{report.stat().st_size/1024:.1f}"
            has_md = "[green]Yes[/green]" if md_file.exists() else "[yellow]No[/yellow]"
            table.add_row(str(idx), timestamp, report.name, size_kb, has_md)
        
        console.print()
        console.print(table)
        console.print()
        
        choice = prompt("Enter report number to view (or Enter to go back): ").strip()
        
        if not choice.isdigit():
            prompt("\nPress Enter to continue...")
            return
        
        idx = int(choice) - 1
        if idx < 0 or idx >= len(display_reports):
            console.print("[yellow]Invalid selection[/yellow]")
            prompt("\nPress Enter to continue...")
            return
        
        selected_report = display_reports[idx]
        try:
            with open(selected_report, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as exc:
            console.print(f"[red]Failed to read report: {exc}[/red]")
            prompt("\nPress Enter to continue...")
            return
        
        metadata = data.get('metadata', {})
        final = data.get('final_analysis', {})
        vt_stats = data.get('vt_analysis', {})
        
        view_mode = prompt("View report as JSON summary or Markdown? [J/m]: ").strip().lower()
        if view_mode not in {"j", "m"}:
            view_mode = "j"
        
        md_file = selected_report.with_suffix('.md')
        
        def show_json_summary():
            summary_table = Table(title="Report Summary", box=box.SIMPLE_HEAVY)
            summary_table.add_column("Field", style="cyan")
            summary_table.add_column("Value", style="yellow")
            summary_table.add_row("File", metadata.get("file_name", metadata.get("basename", "Unknown")))
            summary_table.add_row("SHA256", metadata.get("sha256", "n/a"))
            summary_table.add_row("Generated", datetime.fromtimestamp(selected_report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
            summary_table.add_row("Verdict", final.get("verdict", "unknown"))
            summary_table.add_row("Confidence", f"{final.get('confidence', 0)*100:.1f}%")
            summary_table.add_row("Risk Score", str(final.get("score", "n/a")))
            total_engines = vt_stats.get('malicious',0)+vt_stats.get('suspicious',0)+vt_stats.get('undetected',0) or 1
            summary_table.add_row("VT Detections", f"{vt_stats.get('malicious',0)}/{total_engines}")
            console.print(Panel(summary_table, border_style="green"))
            
            show_full = prompt("Show full JSON payload? [y/N]: ").strip().lower()
            if show_full.startswith('y'):
                try:
                    console.print_json(json.dumps(data, indent=2))
                except Exception:
                    console.print(Panel(json.dumps(data, indent=2), title="JSON", border_style="cyan"))
        
        def show_markdown():
            if not md_file.exists():
                console.print("[yellow]No Markdown report found; falling back to JSON summary.[/yellow]")
                show_json_summary()
                return
            try:
                md_content = md_file.read_text(encoding='utf-8')
                preview_lines = md_content.splitlines()
                preview_text = "\n".join(preview_lines[:120])
                console.print(Panel(
                    Markdown(preview_text or "_(empty report)_"),
                    title=f"{md_file.name} (preview first {min(len(preview_lines),120)} lines)",
                    border_style="cyan",
                    padding=(1,2)
                ))
                
                open_full = prompt("Open full Markdown with less? [y/N]: ").strip().lower()
                if open_full.startswith('y'):
                    less_path = shutil.which("less")
                    if less_path:
                        subprocess.run([less_path, str(md_file)])
                    else:
                        console.print("[yellow]less is not available on this system. Install it or view the file manually.[/yellow]")
            except Exception as exc:
                console.print(f"[red]Failed to render Markdown preview: {exc}[/red]")
        
        if view_mode == "m":
            show_markdown()
        else:
            show_json_summary()
        
        prompt("\nPress Enter to continue...")
    
    def advanced_settings(self):
        """Advanced settings menu."""
        if console:
            settings_panel = Panel.fit(
                "[cyan]Configure advanced options like output directory, Ollama URL, and retry attempts[/cyan]",
                title="[bold yellow]Advanced Settings[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            )
            console.print()
            console.print(settings_panel)
            console.print()
        
        # Output directory
        current_outdir = self.config.get_setting('output_dir', './output')
        new_outdir = prompt(f"Output directory [{current_outdir}]: ", default=current_outdir).strip()
        if new_outdir and new_outdir != current_outdir:
            self.config.set_setting('output_dir', new_outdir)
            console.print(f"[green]✓ Output directory set to: {new_outdir}[/green]")
        
        # Ollama URL
        current_url = self.config.get_setting('ollama_url', 'http://localhost:11434')
        new_url = prompt(f"Ollama URL [{current_url}]: ", default=current_url).strip()
        if new_url and new_url != current_url:
            self.config.set_setting('ollama_url', new_url)
            console.print(f"[green]✓ Ollama URL set to: {new_url}[/green]")
        
        # Retries
        current_retries = self.config.get_setting('retries', 3)
        new_retries = prompt(f"Retry attempts [{current_retries}]: ", default=str(current_retries)).strip()
        if new_retries.isdigit():
            self.config.set_setting('retries', int(new_retries))
            console.print(f"[green]✓ Retry attempts set to: {new_retries}[/green]")
    
    def show_configuration(self):
        """Display current configuration."""
        settings = self.config.get_all_settings()
        
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Setting", style="cyan", width=25)
        table.add_column("Value", style="yellow")
        
        # Hide sensitive values
        for key, value in settings.items():
            if 'api_key' in key.lower():
                display_value = "*" * min(len(str(value)) if value else 0, 20)
            else:
                display_value = str(value)
            table.add_row(key.replace('_', ' ').title(), display_value)
        
        if console:
            config_panel = Panel(
                table,
                title="[bold magenta]Current Configuration[/bold magenta]",
                border_style="magenta",
                box=box.DOUBLE
            )
            console.print()
            console.print(config_panel)
            console.print()
        prompt("\nPress Enter to continue...")
    
    def test_tools(self):
        """Test if CAPA and FLOSS are available."""
        shell_name, rc_file = detect_shell_config()
        
        # Test CAPA
        capa_available, capa_msg = test_shell_tool(shell_name, rc_file, 'capa')
        
        # Test FLOSS
        floss_available, floss_msg = test_shell_tool(shell_name, rc_file, 'floss')
        
        # Create results table
        results_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        results_table.add_column("Tool", style="cyan", width=15)
        results_table.add_column("Status", width=15)
        results_table.add_column("Details", style="yellow")
        
        results_table.add_row(
            "CAPA",
            "[green]✓ Available[/green]" if capa_available else "[red]✗ Not Found[/red]",
            capa_msg
        )
        results_table.add_row(
            "FLOSS",
            "[green]✓ Available[/green]" if floss_available else "[red]✗ Not Found[/red]",
            floss_msg
        )
        
        info_text = f"[cyan]Detected shell:[/cyan] {shell_name or 'None'}\n"
        if rc_file:
            info_text += f"[cyan]RC file:[/cyan] {rc_file}"
        
        if console:
            info_panel = Panel.fit(
                info_text,
                title="[bold cyan]System Information[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            )
            
            tools_panel = Panel(
                results_table,
                title="[bold cyan]Tool Availability Test[/bold cyan]",
                border_style="cyan",
                box=box.DOUBLE
            )
            
            console.print()
            console.print(info_panel)
            console.print()
            console.print(tools_panel)
            console.print()
        
        prompt("\nPress Enter to continue...")
    
    def search_thezoo(self):
        """Search theZoo malware repository and copy files to workspace."""
        # Find theZoo directory
        thezoo_paths = [
            Path("/workspace/theZoo"),
            Path("/opt/workspace/theZoo"),
            Path.home() / "theZoo"
        ]
        
        thezoo_path = None
        for path in thezoo_paths:
            if path.exists() and path.is_dir():
                thezoo_path = path
                break
        
        if not thezoo_path:
            if console:
                console.print("[red]Error: theZoo repository not found.[/red]")
                console.print("[yellow]Expected locations:[/yellow]")
                for path in thezoo_paths:
                    console.print(f"  - {path}")
            else:
                print("Error: theZoo repository not found.")
            prompt("\nPress Enter to continue...")
            return
        
        if console:
            search_panel = Panel.fit(
                "[cyan]Search theZoo malware repository using regex patterns[/cyan]\n"
                "[yellow]Example searches:[/yellow] trojan, ransomware, virus, *.zip, *.exe",
                title="[bold green]theZoo Malware Search[/bold green]",
                border_style="green",
                box=box.ROUNDED
            )
            console.print()
            console.print(search_panel)
            console.print()
        
        # Get search pattern
        pattern = prompt("Enter search pattern (regex, case-insensitive): ").strip()
        if not pattern:
            console.print("[yellow]No pattern entered. Returning to menu.[/yellow]")
            prompt("\nPress Enter to continue...")
            return
        
        # Get file extension filter (optional)
        ext_filter = prompt("Enter file extension filter (e.g., zip, exe, or leave empty for all): ").strip().lower()
        if ext_filter and not ext_filter.startswith('.'):
            ext_filter = '.' + ext_filter
        
        # Common malware file extensions
        default_extensions = ['.zip', '.exe', '.dll', '.elf', '.bin', '.so', '.dylib', '.msi', '.scr', '.bat', '.cmd', '.ps1', '.sh']
        
        if ext_filter:
            file_extensions = [ext_filter]
        else:
            file_extensions = default_extensions
        
        if console:
            console.print(f"\n[cyan]Searching for:[/cyan] [yellow]{pattern}[/yellow]")
            if ext_filter:
                console.print(f"[cyan]File extension:[/cyan] [yellow]{ext_filter}[/yellow]")
            console.print("[dim]This may take a moment...[/dim]\n")
        
        # Search for files
        try:
            pattern_re = re.compile(pattern, re.IGNORECASE)
            matching_files = []
            
            # Recursively search through theZoo directory
            for ext in file_extensions:
                for file_path in thezoo_path.rglob(f"*{ext}"):
                    if file_path.is_file():
                        # Check if pattern matches filename or path
                        filename = file_path.name
                        relative_path = str(file_path.relative_to(thezoo_path))
                        
                        if pattern_re.search(filename) or pattern_re.search(relative_path):
                            matching_files.append(file_path)
            
            if not matching_files:
                if console:
                    console.print(f"[yellow]No files found matching pattern: {pattern}[/yellow]")
                else:
                    print(f"No files found matching pattern: {pattern}")
                prompt("\nPress Enter to continue...")
                return
            
            # Display results in Rich table
            results_table = Table(
                title=f"[bold green]Search Results: {len(matching_files)} file(s) found[/bold green]",
                header_style="bold cyan",
                box=box.ROUNDED,
                show_header=True
            )
            results_table.add_column("#", justify="right", style="cyan", width=5)
            results_table.add_column("File Name", style="yellow bold", width=40)
            results_table.add_column("Path", style="dim cyan", width=50)
            results_table.add_column("Size", justify="right", style="green", width=12)
            results_table.add_column("Type", style="magenta", width=10)
            
            total_size = 0
            for idx, file_path in enumerate(matching_files, 1):
                try:
                    file_size = file_path.stat().st_size
                    total_size += file_size
                    size_str = self._format_size(file_size)
                    file_ext = file_path.suffix.lower() or "no ext"
                    relative_path = str(file_path.relative_to(thezoo_path))
                    
                    results_table.add_row(
                        str(idx),
                        file_path.name,
                        relative_path,
                        size_str,
                        file_ext
                    )
                except Exception as e:
                    # Skip files that can't be accessed
                    continue
            
            if console:
                console.print()
                console.print(results_table)
                console.print()
                console.print(f"[cyan]Total size:[/cyan] [green]{self._format_size(total_size)}[/green]")
                console.print()
            else:
                print(f"\nFound {len(matching_files)} files (Total size: {self._format_size(total_size)})")
            
            # File selection
            selection = prompt("Enter file number(s) to copy to /workspace (comma-separated, or 'all'): ").strip()
            
            if not selection:
                console.print("[yellow]No selection made. Returning to menu.[/yellow]")
                prompt("\nPress Enter to continue...")
                return
            
            # Parse selection
            if selection.lower() == 'all':
                selected_indices = list(range(1, len(matching_files) + 1))
            else:
                try:
                    selected_indices = [int(x.strip()) for x in selection.split(',')]
                except ValueError:
                    console.print("[red]Invalid selection. Please enter numbers separated by commas.[/red]")
                    prompt("\nPress Enter to continue...")
                    return
            
            # Validate indices
            valid_indices = [idx for idx in selected_indices if 1 <= idx <= len(matching_files)]
            if not valid_indices:
                console.print("[red]No valid file numbers selected.[/red]")
                prompt("\nPress Enter to continue...")
                return
            
            # Copy selected files
            workspace_path = Path("/workspace")
            copied_count = 0
            failed_count = 0
            skipped_count = 0
            
            for idx in valid_indices:
                file_path = matching_files[idx - 1]
                dest_path = workspace_path / file_path.name
                
                try:
                    # Check if file exists
                    if dest_path.exists():
                        if console:
                            overwrite = yes_no_dialog(
                                title="File Exists",
                                text=f"{file_path.name} already exists. Overwrite?"
                            ).run()
                            if not overwrite:
                                console.print(f"[yellow]Skipped: {file_path.name}[/yellow]")
                                skipped_count += 1
                                continue
                        else:
                            # Non-interactive mode - skip if exists
                            print(f"Skipped (exists): {file_path.name}")
                            skipped_count += 1
                            continue
                    
                    shutil.copy2(file_path, dest_path)
                    copied_count += 1
                    if console:
                        console.print(f"[green]✓ Copied: {file_path.name}[/green]")
                    else:
                        print(f"Copied: {file_path.name}")
                except Exception as e:
                    failed_count += 1
                    if console:
                        console.print(f"[red]✗ Failed to copy {file_path.name}: {e}[/red]")
                    else:
                        print(f"Failed to copy {file_path.name}: {e}")
            
            if console:
                console.print(f"\n[bold green]Summary:[/bold green]")
                console.print(f"  [green]✓ Successfully copied: {copied_count} file(s)[/green]")
                if skipped_count > 0:
                    console.print(f"  [yellow]⊘ Skipped: {skipped_count} file(s)[/yellow]")
                if failed_count > 0:
                    console.print(f"  [red]✗ Failed: {failed_count} file(s)[/red]")
            else:
                print(f"\nSummary:")
                print(f"  Successfully copied: {copied_count} file(s)")
                if skipped_count > 0:
                    print(f"  Skipped: {skipped_count} file(s)")
                if failed_count > 0:
                    print(f"  Failed: {failed_count} file(s)")
            
        except Exception as e:
            if console:
                console.print(f"[red]Error during search: {e}[/red]")
                import traceback
                console.print("[dim]" + traceback.format_exc() + "[/dim]")
            else:
                print(f"Error during search: {e}")
        
        prompt("\nPress Enter to continue...")
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def run(self):
        """Main menu loop."""
        # Display banner
        if console:
            ZERO_LOGO = """⢋⣴⠒⡝⣿⣿⣿⣿⣿⡿⢋⣥⣶⣿⣿⣿⣿⣿⣿⣶⣦⣍⠻⣿⣿⣿⣿⣿⣷⣿
⢾⣿⣀⣿⡘⢿⣿⡿⠋⠄⠻⠛⠛⠛⠻⠿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣿⣿⣿⣿⣿
⠄⠄⠈⠙⢿⣦⣉⡁⠄⠄⣴⣶⣿⣿⢷⡶⣾⣿⣿⣿⣿⡛⠛⠻⠃⠙⢿⣿⣿⣿
⠄⠄⠄⠄⠄⠈⠉⣀⣀⣴⡟⢩⠁⠩⣝⢂⢨⣿⣿⣿⣿⢟⡛⣳⣶⣤⡘⠿⢋⣡
⠄⠄⠄⠄⠄⠄⠘⣿⣿⣿⣿⣾⣿⣶⣿⣿⣿⣿⣿⣿⣿⣆⣈⣱⣮⣿⣷⡾⠟⠋
⠄⠄⠄⠄⠄⠄⠄⠈⠿⠛⠛⣻⣿⠉⠛⠋⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠸⣿
⠄⠄⠄⠄⢀⡠⠄⢒⣤⣟⠿⣿⣿⣿⣷⣤⣤⣀⣀⣉⣉⣠⣽⣿⣟⠻⣿⣿⡆⢻
⠄⣀⠄⠄⠄⠄⠈⠋⠉⣿⣿⣶⣿⣟⣛⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣼⣿⡇⣸
⣿⠃⠄⠄⠄⠄⠄⠄⠠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣾⣿⣿⣿⣿⣿⣿⠁⢿
⡋⠄⠄⠄⠄⠄⠄⢰⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠄"""
            console.print()
            console.print(Panel(
                Text(ZERO_LOGO, style="bold #6A0DAD"),
                title="[bold #C724B1]Agent-Zero 2.0 Interactive Mode[/bold #C724B1]",
                border_style="#6A0DAD",
                box=box.DOUBLE,
                padding=(1, 2)
            ))
            console.print()
        
        while self.running:
            try:
                choice = self.show_main_menu()
                
                if choice == "1":
                    self.select_llm_model()
                elif choice == "2":
                    self.configure_analysis_options()
                elif choice == "3":
                    self.set_api_keys()
                elif choice == "4":
                    self.run_analysis_interactive()
                elif choice == "5":
                    self.view_reports()
                elif choice == "6":
                    self.advanced_settings()
                elif choice == "7":
                    self.show_configuration()
                elif choice == "8":
                    self.test_tools()
                elif choice == "9":
                    self.search_thezoo()
                elif choice == "10":
                    self.running = False
                    console.print("\n[cyan]Goodbye![/cyan]\n")
                else:
                    console.print("[yellow]Invalid option. Please choose 1-10.[/yellow]\n")
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Exiting...[/yellow]")
                self.running = False
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                if console:
                    import traceback
                    console.print("[dim]" + traceback.format_exc() + "[/dim]")
                prompt("\nPress Enter to continue...")

# ==================== MAIN ====================

def main():
    """Main entry point."""
    try:
        app = InteractiveAgentZero()
        app.run()
    except KeyboardInterrupt:
        if console:
            console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(0)
    except Exception as e:
        if console:
            console.print(f"[red]Fatal error: {e}[/red]")
            import traceback
            traceback.print_exc()
        else:
            print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

