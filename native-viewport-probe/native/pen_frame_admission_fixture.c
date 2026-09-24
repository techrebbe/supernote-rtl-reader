#include "pen_frame_admission_fixture.h"

#include <stddef.h>
#include <string.h>

static int pfa_fail(struct pfa_frame *frame) {
    if (frame != NULL) frame->state = PFA_QUARANTINED;
    return 0;
}

static int pfa_same_scope(struct pfa_scope a, struct pfa_scope b) {
    return a.document_id == b.document_id &&
           a.source_page_index == b.source_page_index &&
           a.page_generation == b.page_generation &&
           a.rotation_epoch == b.rotation_epoch;
}

static uint8_t pfa_target_for(const struct pfa_frame *frame,
                              enum pfa_resource resource) {
    if (resource >= PFA_INK_PLANE_0 && resource <= PFA_INK_PLANE_2)
        return (uint8_t)(resource - PFA_INK_PLANE_0);
    if (resource >= PFA_PAINTER_ALIAS_0 && resource <= PFA_PAINTER_ALIAS_2)
        return frame->alias_target[resource - PFA_PAINTER_ALIAS_0];
    return PFA_NO_PLANE;
}

int pfa_init(struct pfa_frame *frame, struct pfa_scope scope,
             const uint8_t *alias_target, uint8_t alias_count) {
    uint32_t required = 0;
    if (frame == NULL) return 0;
    if (frame->state != PFA_FRESH || frame->required_mask != 0 ||
        frame->bound_mask != 0 || alias_target == NULL || alias_count == 0 ||
        alias_count > 3 || scope.document_id == 0 ||
        scope.page_generation == 0 || scope.rotation_epoch == 0)
        return pfa_fail(frame);
    for (uint8_t i = 0; i < alias_count; ++i)
        if (alias_target[i] > 2) return pfa_fail(frame);
    memset(frame, 0, sizeof(*frame));
    frame->scope = scope;
    frame->alias_count = alias_count;
    for (uint8_t i = 0; i < alias_count; ++i)
        frame->alias_target[i] = alias_target[i];
    for (int resource = PFA_PHYSICAL_INPUT; resource < PFA_RESOURCE_COUNT;
         ++resource) {
        if (resource >= PFA_PAINTER_ALIAS_0 &&
            resource <= PFA_PAINTER_ALIAS_2 &&
            resource - PFA_PAINTER_ALIAS_0 >= alias_count)
            continue;
        required |= PFA_BIT(resource);
    }
    frame->required_mask = required;
    frame->state = PFA_FRESH;
    return 1;
}

int pfa_exclude_input(struct pfa_frame *frame, uint64_t token) {
    if (frame == NULL || frame->state != PFA_FRESH || token == 0)
        return pfa_fail(frame);
    frame->expected[PFA_PHYSICAL_INPUT] =
        (struct pfa_receipt){token, 0, PFA_NO_PLANE};
    frame->bound_mask |= PFA_BIT(PFA_PHYSICAL_INPUT);
    frame->state = PFA_INPUT_EXCLUDED;
    return 1;
}

int pfa_transition_endpoint(struct pfa_frame *frame, uint64_t token,
                            int physical_exclusion_still_proved) {
    if (frame == NULL || frame->state != PFA_INPUT_EXCLUDED || token == 0 ||
        token == frame->expected[PFA_PHYSICAL_INPUT].binding_token ||
        physical_exclusion_still_proved != 1)
        return pfa_fail(frame);
    frame->expected[PFA_PRIVATE_ENDPOINT] =
        (struct pfa_receipt){token, 0, PFA_NO_PLANE};
    frame->bound_mask |= PFA_BIT(PFA_PRIVATE_ENDPOINT);
    frame->state = PFA_ENDPOINT_PRIVATE;
    return 1;
}

int pfa_bind(struct pfa_frame *frame, enum pfa_resource resource,
             struct pfa_scope scope, struct pfa_receipt receipt) {
    if (frame == NULL || (frame->state != PFA_ENDPOINT_PRIVATE &&
                          frame->state != PFA_BINDING) ||
        resource < PFA_INK_PLANE_0 || resource >= PFA_RESOURCE_COUNT ||
        !(frame->required_mask & PFA_BIT(resource)) ||
        (frame->bound_mask & PFA_BIT(resource)) ||
        !pfa_same_scope(frame->scope, scope) || receipt.binding_token == 0 ||
        receipt.private_endpoint !=
            frame->expected[PFA_PRIVATE_ENDPOINT].binding_token ||
        receipt.target_plane != pfa_target_for(frame, resource))
        return pfa_fail(frame);
    frame->expected[resource] = receipt;
    frame->bound_mask |= PFA_BIT(resource);
    frame->state = PFA_BINDING;
    return 1;
}

int pfa_verify(const struct pfa_frame *frame,
               const struct pfa_observation *observed) {
    if (frame == NULL || observed == NULL ||
        (frame->state != PFA_BINDING && frame->state != PFA_CONSTRUCTED &&
         frame->state != PFA_IN_CONTACT) ||
        !pfa_same_scope(frame->scope, observed->scope) ||
        frame->bound_mask != frame->required_mask ||
        observed->active_mask != frame->required_mask ||
        observed->physical_input_excluded != 1 ||
        observed->private_endpoint_active != 1)
        return 0;
    for (int resource = PFA_PHYSICAL_INPUT; resource < PFA_RESOURCE_COUNT;
         ++resource) {
        const struct pfa_receipt *actual = &observed->route[resource];
        const struct pfa_receipt *expected = &frame->expected[resource];
        if (!(frame->required_mask & PFA_BIT(resource))) {
            if (actual->binding_token != 0 || actual->private_endpoint != 0 ||
                actual->target_plane != 0)
                return 0;
            continue;
        }
        if (actual->binding_token != expected->binding_token ||
            actual->private_endpoint != expected->private_endpoint ||
            actual->target_plane != expected->target_plane)
            return 0;
    }
    return 1;
}

int pfa_construct(struct pfa_frame *frame,
                  const struct pfa_observation *observed) {
    if (frame == NULL || frame->state != PFA_BINDING ||
        !pfa_verify(frame, observed))
        return pfa_fail(frame);
    frame->state = PFA_CONSTRUCTED;
    return 1;
}

int pfa_contact_begin(struct pfa_frame *frame,
                      const struct pfa_observation *observed,
                      uint64_t contact_id) {
    if (frame == NULL || frame->state != PFA_CONSTRUCTED || contact_id == 0 ||
        !pfa_verify(frame, observed))
        return pfa_fail(frame);
    frame->active_contact = contact_id;
    frame->state = PFA_IN_CONTACT;
    return 1;
}

int pfa_contact_sample(struct pfa_frame *frame,
                       const struct pfa_observation *observed,
                       uint64_t contact_id) {
    if (frame == NULL || frame->state != PFA_IN_CONTACT ||
        contact_id != frame->active_contact || !pfa_verify(frame, observed))
        return pfa_fail(frame);
    return 1;
}

int pfa_contact_end(struct pfa_frame *frame,
                    const struct pfa_observation *observed,
                    uint64_t contact_id) {
    if (frame == NULL || frame->state != PFA_IN_CONTACT ||
        contact_id != frame->active_contact || !pfa_verify(frame, observed))
        return pfa_fail(frame);
    frame->active_contact = 0;
    frame->state = PFA_CONSTRUCTED;
    return 1;
}

int pfa_teardown(struct pfa_frame *frame,
                 const struct pfa_observation *before_release,
                 const struct pfa_observation *after_release,
                 uint32_t release_ack_mask, int writer_destroyed) {
    if (frame == NULL || frame->state != PFA_CONSTRUCTED ||
        !pfa_verify(frame, before_release) || after_release == NULL ||
        !pfa_same_scope(frame->scope, after_release->scope) ||
        writer_destroyed != 1 || release_ack_mask != frame->required_mask ||
        after_release->active_mask != 0 ||
        after_release->physical_input_excluded != 0 ||
        after_release->private_endpoint_active != 0)
        return pfa_fail(frame);
    for (int resource = PFA_PHYSICAL_INPUT; resource < PFA_RESOURCE_COUNT;
         ++resource)
        if (after_release->route[resource].binding_token != 0 ||
            after_release->route[resource].private_endpoint != 0 ||
            after_release->route[resource].target_plane != 0)
            return pfa_fail(frame);
    frame->state = PFA_CLOSED;
    return 1;
}
