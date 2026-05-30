#pragma once

#include "PoolTags.h"

//Hashnode class
struct HashNode {
    LIST_ENTRY entry;
    HANDLE value;
    ULONGLONG key;

    //Constructor of hashnode
    HashNode(ULONGLONG skey, HANDLE svalue) {
        InitializeListHead(&entry);
        value = svalue;
        key = skey;
    }

    void* operator new(size_t size) {
        void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, OWLY_POOL_TAG_HASH_NODE);
        if (ptr != 0) {
            memset(ptr, 0, size);
        }
        return ptr;
    }

    void operator delete(void* ptr) {
        ExFreePoolWithTag(ptr, OWLY_POOL_TAG_HASH_NODE);
    }
    //fixme needs new and delete operator
};

//Our own Hashmap class - implemented as array of list entries
class HashMap {
    //hash element array
    LIST_ENTRY arr[100];

    ULONGLONG capacity;
    //current size
    ULONGLONG size;
    //dummy node

  public:
    HashMap(const HashMap&) = delete;
    HashMap& operator=(const HashMap&) = delete;

    HashMap() {
        //Initial capacity of hash array
        capacity = 100;
        size = 0;

        //Initialise all elements of array as NULL
        for (ULONGLONG i = 0; i < capacity; i++) {
            InitializeListHead(&arr[i]);
        }
    }
    ~HashMap() {
        clear(NULL);
    }
    // This implements hash function to find index
    // for a key
    ULONGLONG hashCode(ULONGLONG key) {
        return key % capacity;
    }

    //Function to add key value pair
    HANDLE insertNode(ULONGLONG key, HANDLE value) {
        ULONGLONG hashIndex = hashCode(key);

        PLIST_ENTRY head = &arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head) {  // update
            HashNode* pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode*)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key) {
                HANDLE val = pClass->value;
                pClass->value = value;
                return val;
            }
            iterator = iterator->Flink;
        }
        // insert, no key found
        HashNode* temp = new HashNode(key, value);
        if (temp == NULL) {
            return NULL;
        }
        InsertHeadList(head, &(temp->entry));
        size++;
        return value;
    }

    //Function to delete a key value pair
    HANDLE deleteNode(ULONGLONG key) {
        ULONGLONG hashIndex = hashCode(key);

        PLIST_ENTRY head = &arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head) {
            HashNode* pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode*)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key) {
                RemoveEntryList(iterator);
                HANDLE value = pClass->value;
                size--;
                delete pClass;
                return value;
            }
            iterator = iterator->Flink;
        }

        //If not found return null
        return NULL;
    }

    //Function to search the value for a given key
    HANDLE get(ULONGLONG key) {
        ULONGLONG hashIndex = hashCode(key);
        PLIST_ENTRY head = &arr[hashIndex];
        PLIST_ENTRY iterator = head->Flink;
        while (iterator != head) {
            HashNode* pClass;
            //
            // Do some processing.
            //
            pClass = (HashNode*)CONTAINING_RECORD(iterator, HashNode, entry);
            if (pClass->key == key) {
                return pClass->value;
            }
            iterator = iterator->Flink;
        }

        //If not found return null
        return NULL;
    }

    //Return current size
    ULONGLONG sizeofMap() {
        return size;
    }

    //Return true if size is 0
    bool isEmpty() {
        return size == 0;
    }

    // Function to clear the map and free resources
    // Takes a callback to free the HANDLE values
    void clear(void (*freeValue)(HANDLE)) {
        for (ULONGLONG i = 0; i < capacity; i++) {
            PLIST_ENTRY head = &arr[i];
            PLIST_ENTRY iterator = head->Flink;
            while (iterator != head) {
                HashNode* pNode = (HashNode*)CONTAINING_RECORD(iterator, HashNode, entry);
                PLIST_ENTRY next = iterator->Flink;
                
                if (freeValue != nullptr && pNode->value != nullptr) {
                    freeValue(pNode->value);
                }
                
                RemoveEntryList(iterator);
                delete pNode;
                size--;
                iterator = next;
            }
        }
    }
};

