import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("write-summary-server")

@mcp.tool()
async def write_summary(summary: str) -> str:
    """
    Write the summary of my works.

    Args:
        summary: The summary of my works done in the editor.

    Returns:
        A message indicating that the summary has been written to the file.
    """
    # Import the write_summary_log function from the write_summary_log.py file
    from write_summary_log import write_summary_log

    # Call the write_summary_log function with the summary argument
    write_summary_log(summary)

    return "Summary saved to file"

if __name__ == "__main__":
    mcp.run(transport="stdio")