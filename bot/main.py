import asyncio
import discord
import logging
import config

from discord.ext import commands

# --- Logging -----------------------------------------------------------------

handler_console = logging.StreamHandler()
handler_file = logging.FileHandler(filename="discord.log", encoding="utf-8", mode="a")

formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

handler_console.setFormatter(formatter)
handler_file.setFormatter(formatter)

logging.basicConfig(level=logging.INFO, handlers=[handler_console, handler_file])

logger = logging.getLogger(__name__)

# --- Bot setup ---------------------------------------------------------------

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    await bot.tree.sync()
    logger.info(f"Logged in as {bot.user}")

async def main():
    async with bot:
        await bot.load_extension("bot.commands")
        await bot.start(config.DISCORD_TOKEN)

asyncio.run(main())