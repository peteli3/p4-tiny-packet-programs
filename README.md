# Tiny packet programs as a p4-backed DSL

Final project for:  
CS 6114 - Network programming languages
Fall 2018, taught by Nate Foster

## Abstract
Active networking poses an interesting take on leveraging network resources to access the global state with scale in mind. The dream is to have instantaneous freeze and read for gathering information on the state of the network or instantaneous freeze and write for managing the state of the network. But real world constraints make this impossible. Tiny packet programs \cite{tpp} (henceforth referred to as TPP), a variant of active networking, seeks to provide compact primitives for dataplane programming that can leverage network packet travel time to get work done. In this paper, we will discuss our design and implementation of TPP using the p4 language and highlight the following: 1) the specific challenges we faced as a result of choosing p4 to back TPP, and 2) exploring alternative primitives to those specified in the original TPP paper.
