
//
// Copyright (c) 2008-2019 the Urho3D project.
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

/// \file

#pragma once

#include "../Scene/Component.h"

namespace Urho3D
{

class URHO3D_API PrefabComponent : public Component
{
    URHO3D_OBJECT(PrefabComponent, Component);

public:

    /// Construct.
    explicit exPrefabComponent(Context* context);
    /// Destruct.
    ~PrefabComponent() override;

    /// Register object factory.
    static void RegisterObject(Context* context);

    void SetPrefabGUID(const String& guid);
    const String& GetPrefabGUID() const { return prefabGUID_; }

    bool SavePrefab();
    void UndoPrefab();
    void BreakPrefab();

protected:

    /// Handle scene node being assigned at creation.
    void OnNodeSet(Node* node) override;


private:

    void HandlePrefabChanged(StringHash eventType, VariantMap& eventData);

    void LoadPrefabNode();

    String prefabGUID_;

};

}
