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

#pragma once

#ifdef URHO3D_IS_BUILDING
#include "Urho3D.h"
#else
#include <Urho3D/Urho3D.h>
#endif

#include "../Base/TypeInfo.h"

namespace Urho3D
{

/// Reference count structure.
struct RefCount
{
    /// Construct.
    RefCount() :
        refs_(0),
        weakRefs_(0)
    {
    }

    /// Destruct.
    ~RefCount()
    {
        // Set reference counts below zero to fire asserts if this object is still accessed
        refs_ = -1;
        weakRefs_ = -1;
    }

    /// Reference count. If below zero, the object has been destroyed.
    int refs_;
    /// Weak reference count.
    int weakRefs_;
};

class String;
class StringHash;
using ClassID = const void*;

/// Macro to be included in RefCounted derived classes for efficient RTTI
#define URHO3D_REFCOUNTED(typeName, baseTypeName) \
public: \
    using ClassName = typeName; \
    using BaseClassName = baseTypeName; \
    virtual Urho3D::StringHash GetType() const override { return GetTypeInfoStatic()->GetType(); } \
    virtual const Urho3D::String& GetTypeName() const override { return GetTypeInfoStatic()->GetTypeName(); } \
    virtual const Urho3D::TypeInfo* GetTypeInfo() const override { return GetTypeInfoStatic(); } \
    virtual Urho3D::StringHash GetBaseType() const { return GetBaseTypeStatic(); } \
    static Urho3D::StringHash GetTypeStatic() { return GetTypeInfoStatic()->GetType(); } \
    static const Urho3D::String& GetTypeNameStatic() { return GetTypeInfoStatic()->GetTypeName(); } \
    static Urho3D::StringHash GetBaseTypeStatic() \
    { \
        const Urho3D::TypeInfo* baseInfo = GetTypeInfoStatic()->GetBaseTypeInfo(); \
        return baseInfo ? baseInfo->GetType() : StringHash::ZERO; \
    } \
    static const Urho3D::TypeInfo* GetTypeInfoStatic() \
    { \
        static const void* typeId = nullptr; \
        static const Urho3D::TypeInfo typeInfoStatic(#typeName, BaseClassName::GetTypeInfoStatic(), (TypeID)&typeId); \
        return &typeInfoStatic; \
    }

/// Base class for intrusively reference-counted objects. These are noncopyable and non-assignable.
class URHO3D_API RefCounted
{
public:
    /// Construct. Allocate the reference count structure and set an initial self weak reference.
    RefCounted();
    /// Destruct. Mark as expired and also delete the reference count structure if no outside weak references exist.
    virtual ~RefCounted();

    /// Prevent copy construction.
    RefCounted(const RefCounted& rhs) = delete;
    /// Prevent assignment.
    RefCounted& operator =(const RefCounted& rhs) = delete;

    /// Return type hash.
    virtual StringHash GetType() const = 0;
    /// Return type name.
    virtual const String& GetTypeName() const = 0;
    /// Return type info.
    virtual const TypeInfo* GetTypeInfo() const = 0;
    /// Adjust RefCounted subobject is Object. Always return false.
    virtual bool IsObject() const { return false; }
    /// Return type info static.
    static const TypeInfo* GetTypeInfoStatic() { return nullptr; }
    /// Check current type is type of specified type.
    static bool IsTypeOf(StringHash type) { return GetTypeInfoStatic()->IsTypeOf(type); }
    /// Check current type is type of specified type.
    static bool IsTypeOf(const TypeInfo* typeInfo) { return GetTypeInfoStatic()->IsTypeOf(typeInfo); }

    /// Check current type is type of specified class.
    template<typename T> static bool IsTypeOf() { return IsTypeOf(T::GetTypeInfoStatic()); }
    /// Check current instance is type of specified type.
    bool IsInstanceOf(StringHash type) const { return GetTypeInfo()->IsTypeOf(type); }
    /// Check current instance is type of specified type.
    bool IsInstanceOf(const TypeInfo* typeInfo) const { return GetTypeInfo()->IsTypeOf(typeInfo); }
    /// Check current instance is type of specified class.
    template<typename T> bool IsInstanceOf() const { return IsInstanceOf(T::GetTypeInfoStatic()); }
    /// Cast the object to specified most derived class.
    template<typename T> T* Cast() { return IsInstanceOf<T>() ? static_cast<T*>(this) : nullptr; }
    /// Cast the object to specified most derived class.
    template<typename T> const T* Cast() const { return IsInstanceOf<T>() ? static_cast<const T*>(this) : nullptr; }

    /// Increment reference count. Can also be called outside of a SharedPtr for traditional reference counting.
    void AddRef();
    /// Decrement reference count and delete self if no more references. Can also be called outside of a SharedPtr for traditional reference counting.
    void ReleaseRef();
    /// Return reference count.
    int Refs() const;
    /// Return weak reference count.
    int WeakRefs() const;

    /// Return pointer to the reference count structure.
    RefCount* RefCountPtr() { return refCount_; }

private:
    /// Pointer to the reference count structure.
    RefCount* refCount_;
};

}
