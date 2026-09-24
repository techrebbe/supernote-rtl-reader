#ifndef PEN_FRAME_ADMISSION_FIXTURE_H
#define PEN_FRAME_ADMISSION_FIXTURE_H

/* HOST-ONLY MODEL. This fixture does not grab input, redirect Binder, render,
 * construct a real pen engine, or authorize installation on a device. It makes
 * the proposed one-page admission/teardown obligations executable as tests. */
#include <stdint.h>

enum pfa_resource {
    PFA_PHYSICAL_INPUT = 0,
    PFA_PRIVATE_ENDPOINT,
    PFA_INK_PLANE_0,
    PFA_INK_PLANE_1,
    PFA_INK_PLANE_2,
    PFA_PAINTER_ALIAS_0,
    PFA_PAINTER_ALIAS_1,
    PFA_PAINTER_ALIAS_2,
    PFA_BACKGROUND,
    PFA_REFRESH,
    PFA_JAVA_BINDER,
    PFA_NATIVE_BINDER,
    PFA_RESOURCE_COUNT
};

#define PFA_NO_PLANE UINT8_C(255)
#define PFA_BIT(resource) (UINT32_C(1) << (resource))

enum pfa_state {
    PFA_FRESH = 0,
    PFA_INPUT_EXCLUDED,
    PFA_ENDPOINT_PRIVATE,
    PFA_BINDING,
    PFA_CONSTRUCTED,
    PFA_IN_CONTACT,
    PFA_CLOSED,
    PFA_QUARANTINED
};

struct pfa_scope {
    uint64_t document_id;
    uint32_t source_page_index;
    uint64_t page_generation;
    uint64_t rotation_epoch;
};

struct pfa_receipt {
    uint64_t binding_token;
    uint64_t private_endpoint;
    uint8_t target_plane;
};

/* An independent fake environment supplies observations at every boundary.
 * A real implementation would need authenticated live witnesses, not values
 * copied from the model's expected receipts. */
struct pfa_observation {
    struct pfa_scope scope;
    uint32_t active_mask;
    uint8_t physical_input_excluded;
    uint8_t private_endpoint_active;
    struct pfa_receipt route[PFA_RESOURCE_COUNT];
};

struct pfa_frame {
    enum pfa_state state;
    struct pfa_scope scope;
    uint8_t alias_count;
    uint8_t alias_target[3];
    uint32_t required_mask;
    uint32_t bound_mask;
    uint64_t active_contact;
    struct pfa_receipt expected[PFA_RESOURCE_COUNT];
};

/* frame must be zero-initialized; one object admits at most one page session. */
int pfa_init(struct pfa_frame *frame, struct pfa_scope scope,
             const uint8_t *alias_target, uint8_t alias_count);
int pfa_exclude_input(struct pfa_frame *frame, uint64_t token);
int pfa_transition_endpoint(struct pfa_frame *frame, uint64_t token,
                            int physical_exclusion_still_proved);
int pfa_bind(struct pfa_frame *frame, enum pfa_resource resource,
             struct pfa_scope scope, struct pfa_receipt receipt);
int pfa_verify(const struct pfa_frame *frame,
               const struct pfa_observation *observed);
int pfa_construct(struct pfa_frame *frame,
                  const struct pfa_observation *observed);
int pfa_contact_begin(struct pfa_frame *frame,
                      const struct pfa_observation *observed,
                      uint64_t contact_id);
int pfa_contact_sample(struct pfa_frame *frame,
                       const struct pfa_observation *observed,
                       uint64_t contact_id);
int pfa_contact_end(struct pfa_frame *frame,
                    const struct pfa_observation *observed,
                    uint64_t contact_id);
int pfa_teardown(struct pfa_frame *frame,
                 const struct pfa_observation *before_release,
                 const struct pfa_observation *after_release,
                 uint32_t release_ack_mask, int writer_destroyed);

#endif
