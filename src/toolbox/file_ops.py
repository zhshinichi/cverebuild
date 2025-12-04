import os

from agentlib.lib import tools

@tools.tool
def write_to_file(content: str, filename: str):
    """
    Writes the provided content to the provided file.
    :param content: Content to put in the file
    :param filename: Relative path to the file (relative to project root, e.g., 'backend/setup.py')
    :return: If successful or not
    """
    
    cur_dir = os.getcwd()
    repo_path = os.environ.get('REPO_PATH', '')
    
    # 智能路径处理：去除重复的项目目录前缀
    # 如果 filename 以 repo_path 开头，去掉它
    if repo_path:
        repo_name = repo_path.rstrip('/')
        if filename.startswith(repo_name + '/'):
            filename = filename[len(repo_name) + 1:]
            print(f"[write_to_file] Stripped duplicate prefix, using: {filename}")
    
    os.chdir("simulation_environments/" + repo_path)

    try:
        # 确保目录存在
        dir_name = os.path.dirname(filename)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        
        with open(filename, "w", encoding='utf-8') as outfile:
            for line in content.split("\n"):
                outfile.write(line + "\n")
        return "Success"
    except FileNotFoundError as e:
        print(f"[write_to_file] FileNotFoundError: {e}")
        return f"Error: Intermediate directory does not exist. Details: {e}"
    except PermissionError:
        print("[write_to_file] No permission")
        return f"Error: Permission denied to write to the file '{filename}'."
    except Exception as e:
        print(f"[write_to_file] Unexpected error: {e}")
        return f"Error: {e}"
    finally:
        os.chdir(cur_dir)

@tools.tool
def get_file(file_path: str, offset: int, num_lines:int) -> str:
    """
    Open the given file and return its content.
    A total of num_lines_to_show lines will be shown starting from offset.
    There is a maximum of 200 lines that can be shown at once.
    You can display other lines in the given file by changing the offset.
    IMPORTANT: You are in the root directory of the project, so if you want to open a file in the project directory then use the relative path, otherwise for other files on the system use the absolute path.

    :param file_path: The path of the file to open.
    :param offset: The line number to start reading the file from.
    :return: lines_to_show lines of the file_path starting from the specified offset.
             More specifically, the output will be in the format:
             ```
             [File: <file_path> (<total_lines> lines total)]
             (<offset> lines above)
             <line_number>: <line_content>
             ...
             (<lines_below> lines below)
             ```
    """

    cur_dir = os.getcwd()
    os.chdir("simulation_environments/" + os.environ['REPO_PATH'])

    try: 
        # Check if the file exists
        if not os.path.exists(file_path):
            return f"File {file_path} does not exist."

        file_view = ""

        with open(file_path, 'r', encoding='utf-8') as file:
            log_context = file.read()
        
        # Grab the total number of lines in the file
        file_lines_tot = len(log_context.splitlines())

        num_lines_to_show = min(200, num_lines)

        # Grab the lines from offset to self.MAX_LINES_PER_VIEW
        file_lines_in_scope = log_context.splitlines()[offset:offset+num_lines_to_show]

        # If we have no lines left, tell it to the llm.
        if len(file_lines_in_scope) == 0:
            return "No more lines to show."
        
        file_lines_in_scope = '\n'.join(file_lines_in_scope)
        
        # Building the view!
        file_view = f"\n[File: {file_path} ({file_lines_tot} lines total)]\n"
        file_view += f"({offset} lines above)\n"

        # Add the lines we are showing, add the line numbers at the beginning
        for idx, line in enumerate(file_lines_in_scope.splitlines()):
            idx = idx + offset
            file_view += f"{idx + 1}: {line}\n"

        # Finally, added the remaining line
        lines_below = file_lines_tot - (offset + num_lines_to_show)
        if lines_below > 0:
            file_view += f"({lines_below} lines below)\n"
        else:
            file_view += f"(No lines below)\n"        
        return file_view
    finally:
        os.chdir(cur_dir)

# @tools.tool
# def get_file(filename: str) -> str:
#     """
#     This tool reads the content of a file and returns it as a string.
#     You need to provide a relative path from the root directory of the project

#     :param filename: The path to the file to read.
#     :return: The content of the file.
#     """

#     # print(f"Trying to read {filename}...\nProceed? y/N")
#     # p = input()
#     # if p!='y':
#     #     return "Unable to execute, permission denied"
    
#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])

#     data = ""
#     try:
#         with open(filename, 'r') as file:
#             data = file.read()
#     except FileNotFoundError:
#         return "File does not exist"
#     finally:
#         os.chdir(cur_dir)

#     return data