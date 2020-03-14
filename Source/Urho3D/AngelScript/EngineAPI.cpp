//
// Copyright (c) 2008-2020 the Urho3D project.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include "../Precompiled.h"

#include "../AngelScript/APITemplates.h"
#include "../Engine/Engine.h"

namespace Urho3D
{

static Engine* GetEngine()
{
    return GetScriptContext()->GetSubsystem<Engine>();
}

static void RegisterEngine(asIScriptEngine* engine)
{
    RegisterObject<Engine>(engine, "Engine");
    engine->RegisterObjectMethod("Engine", "void RunFrame()", asMETHOD(Engine, RunFrame), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void Exit()", asMETHOD(Engine, Exit), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void DumpProfiler()", asMETHOD(Engine, DumpProfiler), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void DumpResources(bool=false)", asMETHOD(Engine, DumpResources), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void DumpMemory()", asMETHOD(Engine, DumpMemory), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "Console@+ CreateConsole()", asMETHOD(Engine, CreateConsole), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "DebugHud@+ CreateDebugHud()", asMETHOD(Engine, CreateDebugHud), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_minFps(int)", asMETHOD(Engine, SetMinFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "int get_minFps() const", asMETHOD(Engine, GetMinFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_maxFps(int)", asMETHOD(Engine, SetMaxFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "int get_maxFps() const", asMETHOD(Engine, GetMaxFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_timeStepSmoothing(int)", asMETHOD(Engine, SetTimeStepSmoothing), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "int get_timeStepSmoothing() const", asMETHOD(Engine, GetTimeStepSmoothing), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_maxInactiveFps(int)", asMETHOD(Engine, SetMaxInactiveFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "int get_maxInactiveFps() const", asMETHOD(Engine, GetMaxInactiveFps), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_pauseMinimized(bool)", asMETHOD(Engine, SetPauseMinimized), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "bool get_pauseMinimized() const", asMETHOD(Engine, GetPauseMinimized), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "void set_autoExit(bool)", asMETHOD(Engine, SetAutoExit), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "bool get_autoExit() const", asMETHOD(Engine, GetAutoExit), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "bool get_initialized() const", asMETHOD(Engine, IsInitialized), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "bool get_exiting() const", asMETHOD(Engine, IsExiting), asCALL_THISCALL);
    engine->RegisterObjectMethod("Engine", "bool get_headless() const", asMETHOD(Engine, IsHeadless), asCALL_THISCALL);
    engine->RegisterGlobalFunction("Engine@+ get_engine()", asFUNCTION(GetEngine), asCALL_CDECL);
}

void RegisterEngineAPI(asIScriptEngine* engine)
{
    RegisterEngine(engine);
}

}
