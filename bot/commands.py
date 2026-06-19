"""
bot/commands.py — Discord event listeners and slash commands for the setup phase.
 
Covers:
- Welcome message on guild join
- Attachment listener (logs uploads, no analysis yet)
- /help  — describes what scOWL does
- /status — reports bot uptime and basic counters
"""

import logging
import os


from analysis.model import FileInfo
from analysis.utils import compute_hashes, safe_filename, format_size
from analysis.dispatcher import dispatch
from datetime import datetime, timezone
from config import WELCOME_CHANNEL_NAME, WATCHED_CHANNEL_NAMES, MAX_FILE_SIZE_BYTES, TEMP_DOWNLOAD_DIR
from discord.ext import commands
from discord import app_commands, Embed, Interaction
from reporting.embed_builder import build_result_embed


logger = logging.getLogger(__name__)

class ScowlEvents(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.start_time = datetime.now(timezone.utc)
        self.watched = (
            " · ".join(f"`#{name}`" for name in WATCHED_CHANNEL_NAMES)
            if WATCHED_CHANNEL_NAMES
            else "All channels"
        )

    # --- Cog listeners ----------------------------------------------------------------

    @commands.Cog.listener()
    async def on_guild_join(self, guild):
        target_channel = None
        if WELCOME_CHANNEL_NAME:
            target_channel = next(
                (c for c in guild.text_channels if c.name.lower() == WELCOME_CHANNEL_NAME),
                None,
            )
        target_channel = target_channel or guild.system_channel
        if target_channel is not None:
            embed = Embed(
                title="scOWL is watching",
                description=(
                    "Drop any file in a watched channel and scOWL will automatically "
                    "run a static analysis — no commands needed.\n\n"
                    "Supported formats: **PE · ELF · PDF · Office · Scripts**"
                ),
                color=0x5865F2,
            )
            embed.set_author(
                name="Static malware triage",
                icon_url=self.bot.user.avatar.url
            )
            embed.add_field(name="Watching", value=self.watched, inline=False)
            embed.add_field(name="Version", value="v0.1", inline=True)
            embed.add_field(name="Commands", value="`/help` · `/status` · `/scan`", inline=True)
            embed.set_footer(text="scOWL · Use /help for the full command list")
            await target_channel.send(embed=embed)
            
    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author == self.bot.user:
            return
        if WATCHED_CHANNEL_NAMES and message.channel.name not in WATCHED_CHANNEL_NAMES:
            return

        for attachment in message.attachments:
            if attachment.size > MAX_FILE_SIZE_BYTES:
                logger.warning(f"file too large, skipped | id={attachment.id} filename={attachment.filename} size={attachment.size} limit={MAX_FILE_SIZE_BYTES}")
                continue

            file_info = FileInfo(
                file_id=attachment.id,
                filename=attachment.filename,
                size=attachment.size,
                channel=message.channel.name,
                author=str(message.author),
                content_type=attachment.content_type or "",
            )

            dest = os.path.join(
                TEMP_DOWNLOAD_DIR,
                safe_filename(attachment.id, attachment.filename)
            )
            os.makedirs(TEMP_DOWNLOAD_DIR, exist_ok=True)

            try:
                await attachment.save(dest)
            except Exception:
                logger.exception(f"download failed | id={attachment.id} filename={attachment.filename}")
                continue

            logger.info(f"file received | id={attachment.id} filename={attachment.filename} size={attachment.size} author={message.author} channel={message.channel.name}")
            file_info.path = dest

            try:
                hashes = compute_hashes(dest)
            except Exception:
                logger.exception(f"hashing failed | id={attachment.id} filename={attachment.filename}")
                continue

            logger.debug(f"hashes computed | id={attachment.id} sha256={hashes['sha256']} sha1={hashes['sha1']} md5={hashes['md5']}")

            file_info.sha256 = hashes["sha256"]
            file_info.sha1 = hashes["sha1"]
            file_info.md5 = hashes["md5"]
            
            # ---- Analysis ----
            result = dispatch(file_info)
            if result.errors:
                logger.warning(f"analysis errors | id={attachment.id} errors={result.errors}")
            
            # ---- Embed message to user ----
            
            # ---- Received embed ----
            received_embed = Embed(
                title="📥 File received",
                color=0x5865F2,
            )
            received_embed.set_author(name="scOWL — Static malware triage")
            received_embed.add_field(name="Filename", value=file_info.filename, inline=False)
            received_embed.add_field(name="Size", value=format_size(file_info.size), inline=False)
            received_embed.add_field(name="Type", value=file_info.content_type, inline=False)
            received_embed.add_field(name="Author", value=file_info.author, inline=False)
            received_embed.add_field(name="SHA-256", value=file_info.sha256[:16] + "...", inline=False)
            received_embed.set_footer(text=f"scOWL · {len(result.indicators)} indicator(s) found")
            
            await message.reply(embed=received_embed)
            
            # --- Analysis result embed ----
            await message.reply(embed=build_result_embed(result))
            
            
        
    
    # --- SLASH COMMANDS ---------------------------------------------------------------

    @app_commands.command(name="help", description="Overview of scOWL and its analysis capabilities")
    async def help(self, interaction: Interaction):
        embed = Embed(
            title="scOWL — Static malware triage",
            description=(
                "scOWL automatically analyzes every file uploaded in watched channels "
                "and reports a risk score, ATT&CK mapping and VirusTotal reputation.\n\n"
                "You can also trigger a manual scan with `/scan`."
            ),
            color=0x5865F2,
        )
        embed.set_author(name="Help")
        embed.add_field(
            name="Supported formats",
            value="PE · ELF · PDF · Office · PS1 / BAT / VBS / JS",
            inline=False,
        )
        embed.add_field(name="Watching", value=self.watched, inline=False)
        embed.add_field(name="/help", value="This message", inline=True)
        embed.add_field(name="/status", value="Bot uptime and stats", inline=True)
        embed.add_field(name="/scan", value="Manual scan (coming soon)", inline=True)
        embed.add_field(
            name="Source",
            value="[github.com/HalfTimeOfLife/scOWL](https://github.com/HalfTimeOfLife/scOWL)",
            inline=False,
        )
        embed.set_footer(text="scOWL · Static malware triage")
        await interaction.response.send_message(embed=embed)
    
    @app_commands.command(name="status", description="Current bot status and runtime statistics")
    async def status(self, interaction: Interaction):
        uptime = datetime.now(timezone.utc) - self.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        embed = Embed(title="scOWL status", color=0x5865F2)
        embed.set_author(name="Runtime statistics")
        embed.add_field(name="Uptime", value=f"{hours}h {minutes}m {seconds}s", inline=True)
        embed.add_field(name="Latency", value=f"{round(self.bot.latency * 1000)} ms", inline=True)
        embed.add_field(name="Servers", value=str(len(self.bot.guilds)), inline=True)
        embed.add_field(name="Watching", value=self.watched, inline=False)
        embed.add_field(name="Version", value="v0.1", inline=True)
        embed.set_footer(text="scOWL · Use /help for the full command list")
        await interaction.response.send_message(embed=embed)
        

                     
async def setup(bot):
    await bot.add_cog(ScowlEvents(bot))