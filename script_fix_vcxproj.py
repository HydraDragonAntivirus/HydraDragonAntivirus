import re

with open('Owlyshield/owlyshield_minifilter/OwlyshieldRansomFilter/OwlyshieldRansomFilter.vcxproj', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove OwlyOptionalRedDbg variables perfectly.
content = re.sub(r'<OwlyOptionalRedDbgLibDirs>.*?</OwlyOptionalRedDbgLibDirs>\s*', '', content)
content = re.sub(r'<OwlyOptionalRedDbgIncludeDirs>.*?</OwlyOptionalRedDbgIncludeDirs>\s*', '', content)
content = re.sub(r'<OwlyOptionalRedDbgDeps>.*?</OwlyOptionalRedDbgDeps>\s*', '', content)
content = re.sub(r'<OwlyOptionalRedDbgDefines>.*?</OwlyOptionalRedDbgDefines>\s*', '', content)

# 2. Remove OwlyOptionalHyperDbg variables
content = re.sub(r'<OwlyOptionalHyperDbgLibDirs>.*?</OwlyOptionalHyperDbgLibDirs>\s*', '', content)
content = re.sub(r'<OwlyOptionalHyperDbgIncludeDirs>.*?</OwlyOptionalHyperDbgIncludeDirs>\s*', '', content)
content = re.sub(r'<OwlyOptionalHyperDbgDeps>.*?</OwlyOptionalHyperDbgDeps>\s*', '', content)
content = re.sub(r'<OwlyOptionalHyperDbgDefines>.*?</OwlyOptionalHyperDbgDefines>\s*', '', content)

# 3. Clean up the actual project dependencies inside ItemDefinitionGroup
content = content.replace('$(OwlyOptionalRedDbgLibDirs);$(OwlyOptionalHyperDbgLibDirs);', '')
content = content.replace('$(OwlyOptionalRedDbgDeps)$(OwlyOptionalHyperDbgDeps)', '')

# Handle IncludeDirectories properly
content = re.sub(r'<AdditionalIncludeDirectories>\$\(OwlyOptionalRedDbgIncludeDirs\)[^<]*<%\(AdditionalIncludeDirectories\)></AdditionalIncludeDirectories>', r'<AdditionalIncludeDirectories>%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>', content)

# Handle PreprocessorDefinitions. Replace `$(OwlyOptionalRedDbgDefines)$(OwlyOptionalHyperDbgDefines)POOL_NX_OPTIN=1` with `POOL_NX_OPTIN=1`
content = content.replace('$(OwlyOptionalRedDbgDefines)$(OwlyOptionalHyperDbgDefines)POOL_NX_OPTIN=1', 'POOL_NX_OPTIN=1')

# 4. Remove the <PropertyGroup Condition=... and Exists(...)> logic
content = re.sub(r' and Exists\(\'\$\(ProjectDir\)\.\.\\\\HyperDbg\\\\hyperdbg\\\\build\\\\bin\\\\[a-zA-Z\s]+\\\\hyperhv\.lib\'\)', '', content)

# 5. Remove RedDbg Source files EXCEPT CppSupport.cpp
content = re.sub(r'\s*<ClCompile Include="..\\RedDbg\\RedDbg\\Source\\HyperVisor\\.*?/>', '', content)
content = re.sub(r'\s*<ClCompile Include="..\\RedDbg\\RedDbg\\Source\\TransparentMode\\.*?/>', '', content)
content = re.sub(r'\s*<ClCompile Include="..\\RedDbg\\RedDbg\\Source\\Debugger\\Driver\\DrvMain.cpp" />', '', content)
content = re.sub(r'\s*<ClCompile Include="..\\RedDbg\\RedDbg\\Source\\Log\\.*?/>', '', content)
content = re.sub(r'\s*<MASM Include="..\\RedDbg\\RedDbg\\Source\\Debugger\\Driver\\.*?/>', '', content)

# 6. Remove RedDbg Includes
content = re.sub(r'\s*<ClInclude Include="..\\RedDbg\\RedDbg\\Include\\.*?/>', '', content)

# 7. Remove OwlyVmmBridge files
content = re.sub(r'\s*<ClCompile Include="OwlyVmmBridge\.c" />', '', content)
content = re.sub(r'\s*<ClCompile Include="OwlyAmdVmmBridge\.cpp" />', '', content)

with open('Owlyshield/owlyshield_minifilter/OwlyshieldRansomFilter/OwlyshieldRansomFilter.vcxproj', 'w', encoding='utf-8') as f:
    f.write(content)
